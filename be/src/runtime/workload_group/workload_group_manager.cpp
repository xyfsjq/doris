// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "workload_group_manager.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "pipeline/task_scheduler.h"
#include "runtime/memory/mem_tracker_limiter.h"
#include "runtime/workload_group/workload_group.h"
#include "util/mem_info.h"
#include "util/threadpool.h"
#include "util/time.h"
#include "vec/exec/scan/scanner_scheduler.h"

namespace doris {

WorkloadGroupPtr WorkloadGroupMgr::get_or_create_workload_group(
        const WorkloadGroupInfo& workload_group_info) {
    {
        std::shared_lock<std::shared_mutex> r_lock(_group_mutex);
        if (LIKELY(_workload_groups.count(workload_group_info.id))) {
            auto workload_group = _workload_groups[workload_group_info.id];
            workload_group->check_and_update(workload_group_info);
            return workload_group;
        }
    }

    auto new_task_group = std::make_shared<WorkloadGroup>(workload_group_info);
    std::lock_guard<std::shared_mutex> w_lock(_group_mutex);
    if (_workload_groups.count(workload_group_info.id)) {
        auto workload_group = _workload_groups[workload_group_info.id];
        workload_group->check_and_update(workload_group_info);
        return workload_group;
    }
    _workload_groups[workload_group_info.id] = new_task_group;
    return new_task_group;
}

void WorkloadGroupMgr::get_related_workload_groups(
        const std::function<bool(const WorkloadGroupPtr& ptr)>& pred,
        std::vector<WorkloadGroupPtr>* task_groups) {
    std::shared_lock<std::shared_mutex> r_lock(_group_mutex);
    for (const auto& [id, workload_group] : _workload_groups) {
        if (pred(workload_group)) {
            task_groups->push_back(workload_group);
        }
    }
}

WorkloadGroupPtr WorkloadGroupMgr::get_task_group_by_id(uint64_t tg_id) {
    std::shared_lock<std::shared_mutex> r_lock(_group_mutex);
    if (_workload_groups.find(tg_id) != _workload_groups.end()) {
        return _workload_groups.at(tg_id);
    }
    return nullptr;
}

void WorkloadGroupMgr::delete_workload_group_by_ids(std::set<uint64_t> used_wg_id) {
    int64_t begin_time = MonotonicMillis();
    // 1 get delete group without running queries
    std::vector<WorkloadGroupPtr> deleted_task_groups;
    int old_wg_size = 0;
    int new_wg_size = 0;
    {
        std::lock_guard<std::shared_mutex> write_lock(_group_mutex);
        old_wg_size = _workload_groups.size();
        for (auto iter = _workload_groups.begin(); iter != _workload_groups.end(); iter++) {
            uint64_t wg_id = iter->first;
            auto workload_group_ptr = iter->second;
            if (used_wg_id.find(wg_id) == used_wg_id.end()) {
                workload_group_ptr->shutdown();
                LOG(INFO) << "[topic_publish_wg] shutdown wg:" << wg_id;
            }
            // wg is shutdown and running rum = 0, its resource can be released in BE
            if (workload_group_ptr->can_be_dropped()) {
                LOG(INFO) << "[topic_publish_wg]There is no query in wg" << wg_id << ", delete it.";
                deleted_task_groups.push_back(workload_group_ptr);
            }
        }
    }

    // 2 stop active thread
    for (auto& wg : deleted_task_groups) {
        // There is not lock here, but the tg may be released by another
        // thread, so that we should use shared ptr here, not use wg_id
        wg->try_stop_schedulers();
    }

    // 3 release resource in memory
    {
        std::lock_guard<std::shared_mutex> write_lock(_group_mutex);
        for (auto& wg : deleted_task_groups) {
            _workload_groups.erase(wg->id());
        }
        new_wg_size = _workload_groups.size();
    }

    // 4 clear cgroup dir
    // NOTE(wb) currently we use rmdir to delete cgroup path,
    // this action may be failed until task file is cleared which means all thread are stopped.
    // So the first time to rmdir a cgroup path may failed.
    // Using cgdelete has no such issue.
    {
        if (config::doris_cgroup_cpu_path != "") {
            std::lock_guard<std::shared_mutex> write_lock(_init_cg_ctl_lock);
            if (!_cg_cpu_ctl) {
                _cg_cpu_ctl = std::make_unique<CgroupV1CpuCtl>();
            }
            if (!_is_init_succ) {
                Status ret = _cg_cpu_ctl->init();
                if (ret.ok()) {
                    _is_init_succ = true;
                } else {
                    LOG(INFO) << "[topic_publish_wg]init workload group mgr cpu ctl failed, "
                              << ret.to_string();
                }
            }
            if (_is_init_succ) {
                Status ret = _cg_cpu_ctl->delete_unused_cgroup_path(used_wg_id);
                if (!ret.ok()) {
                    LOG(WARNING) << "[topic_publish_wg]" << ret.to_string();
                }
            }
        }
    }
    int64_t time_cost_ms = MonotonicMillis() - begin_time;
    LOG(INFO) << "[topic_publish_wg]finish clear unused workload group, time cost: " << time_cost_ms
              << "ms, deleted group size:" << deleted_task_groups.size()
              << ", before wg size=" << old_wg_size << ", after wg size=" << new_wg_size;
}

struct WorkloadGroupMemInfo {
    int64_t total_mem_used = 0;
    std::list<std::shared_ptr<MemTrackerLimiter>> tracker_snapshots =
            std::list<std::shared_ptr<MemTrackerLimiter>>();
};

void WorkloadGroupMgr::refresh_wg_weighted_memory_ratio() {
    std::shared_lock<std::shared_mutex> r_lock(_group_mutex);

    // 1. make all workload groups memory snapshots(refresh workload groups total memory used at the same time)
    // and calculate total memory used of all queries.
    int64_t all_queries_mem_used = 0;
    std::unordered_map<uint64_t, WorkloadGroupMemInfo> wgs_mem_info;
    for (auto& [wg_id, wg] : _workload_groups) {
        wgs_mem_info[wg_id].total_mem_used =
                wg->make_memory_tracker_snapshots(&wgs_mem_info[wg_id].tracker_snapshots);
        all_queries_mem_used += wgs_mem_info[wg_id].total_mem_used;
    }
    if (all_queries_mem_used <= 0) {
        return;
    }

    // 2. calculate weighted ratio.
    // process memory used is actually bigger than all_queries_mem_used,
    // because memory of page cache, allocator cache, segment cache etc. are included
    // in proc_vm_rss.
    // we count these cache memories equally on workload groups.
    auto process_memory_usage = GlobalMemoryArbitrator::process_memory_usage();
    all_queries_mem_used = std::min(process_memory_usage, all_queries_mem_used);
    double ratio = (double)process_memory_usage / (double)all_queries_mem_used;
    if (ratio <= 1.25) {
        std::string debug_msg =
                fmt::format("\nProcess Memory Summary: {}, {}, all quries mem: {}",
                            doris::GlobalMemoryArbitrator::process_memory_used_details_str(),
                            doris::GlobalMemoryArbitrator::sys_mem_available_details_str(),
                            PrettyPrinter::print(all_queries_mem_used, TUnit::BYTES));
        LOG_EVERY_T(INFO, 10) << debug_msg;
    }

    for (auto& wg : _workload_groups) {
        // 3.1 calculate query weighted memory limit of task group
        auto wg_mem_limit = wg.second->memory_limit();
        auto wg_query_count = wgs_mem_info[wg.first].tracker_snapshots.size();
        int64_t query_weighted_mem_limit =
                wg_query_count ? (wg_mem_limit + wg_query_count) / wg_query_count : wg_mem_limit;

        // 3.2 set all workload groups weighted memory ratio and all query weighted memory limit and ratio.
        wg.second->set_weighted_memory_ratio(ratio);
        for (const auto& query : wg.second->queries()) {
            auto query_ctx = query.second.lock();
            if (!query_ctx) {
                continue;
            }
            query_ctx->set_weighted_memory(query_weighted_mem_limit, ratio);
        }

        // 3.3 only print debug logs, if workload groups is_high_wartermark or is_low_wartermark.
        auto weighted_mem_used = int64_t(wgs_mem_info[wg.first].total_mem_used * ratio);
        bool is_high_wartermark =
                (weighted_mem_used >
                 ((double)wg_mem_limit * wg.second->spill_threashold_high_water_mark() / 100));
        bool is_low_wartermark =
                (weighted_mem_used >
                 ((double)wg_mem_limit * wg.second->spill_threshold_low_water_mark() / 100));
        std::string debug_msg;
        if (is_high_wartermark || is_low_wartermark) {
            debug_msg = fmt::format(
                    "\nWorkload Group {}: mem limit: {}, mem used: {}, weighted mem used: {}, used "
                    "ratio: {}, query "
                    "count: {}, query_weighted_mem_limit: {}",
                    wg.second->name(), PrettyPrinter::print(wg_mem_limit, TUnit::BYTES),
                    PrettyPrinter::print(wgs_mem_info[wg.first].total_mem_used, TUnit::BYTES),
                    PrettyPrinter::print(weighted_mem_used, TUnit::BYTES),
                    (double)weighted_mem_used / wg_mem_limit, wg_query_count,
                    PrettyPrinter::print(query_weighted_mem_limit, TUnit::BYTES));

            debug_msg += "\n  Query Memory Summary:";
            // check whether queries need to revoke memory for task group
            for (const auto& query_mem_tracker : wgs_mem_info[wg.first].tracker_snapshots) {
                debug_msg += fmt::format(
                        "\n    MemTracker Label={}, Parent Label={}, Used={}, WeightedUsed={}, "
                        "Peak={}",
                        query_mem_tracker->label(), query_mem_tracker->parent_label(),
                        PrettyPrinter::print(query_mem_tracker->consumption(), TUnit::BYTES),
                        PrettyPrinter::print(int64_t(query_mem_tracker->consumption() * ratio),
                                             TUnit::BYTES),
                        PrettyPrinter::print(query_mem_tracker->peak_consumption(), TUnit::BYTES));
            }
            LOG_EVERY_T(INFO, 1) << debug_msg;
        } else {
            continue;
        }
    }
}

void WorkloadGroupMgr::stop() {
    for (auto iter = _workload_groups.begin(); iter != _workload_groups.end(); iter++) {
        iter->second->try_stop_schedulers();
    }
}

} // namespace doris
