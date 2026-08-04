import Darwin
import Foundation

/// What this process is holding: how many threads, and how much memory the
/// system counts against it.
///
/// The alternative is Xcode's Debug Navigator or Instruments, which need a Mac
/// with the app running under a debugger. A device being tested by someone who
/// has neither still has to be able to answer "did that come back down", so the
/// app reads its own numbers and writes them to the log it already keeps.
///
/// Both come from the Mach task port, which a process may always ask about
/// itself; neither needs an entitlement.
enum ProcessStats {
    /// A reading, in the units the log prints.
    struct Sample {
        let threads: Int
        /// `phys_footprint` — what iOS holds against the app for jetsam, which
        /// is the figure worth watching. Not resident size, which counts pages
        /// the app does not pay for.
        let footprintBytes: UInt64

        var summary: String {
            let mib = Double(footprintBytes) / (1024 * 1024)
            return String(format: "threads=%d footprint=%.1fMiB", threads, mib)
        }
    }

    static func sample() -> Sample {
        Sample(threads: threadCount(), footprintBytes: footprint())
    }

    /// Live threads in this task.
    ///
    /// `task_threads` hands back an array of send rights, and every one of them
    /// has to be given back or this leaks a port per call — which would make
    /// the counter it exists to check wrong in the direction that matters.
    private static func threadCount() -> Int {
        var list: thread_act_array_t?
        var count = mach_msg_type_number_t(0)
        guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS,
              let list
        else { return 0 }
        for index in 0..<Int(count) {
            mach_port_deallocate(mach_task_self_, list[index])
        }
        vm_deallocate(
            mach_task_self_,
            vm_address_t(UInt(bitPattern: list)),
            vm_size_t(Int(count) * MemoryLayout<thread_t>.stride)
        )
        return Int(count)
    }

    private static func footprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), rebound, &count)
            }
        }
        return result == KERN_SUCCESS ? UInt64(info.phys_footprint) : 0
    }
}
