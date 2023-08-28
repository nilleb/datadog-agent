#ifndef _CONSTANTS_ENUMS_H
#define _CONSTANTS_ENUMS_H

enum event_type {
    EVENT_ANY = 0,
    EVENT_FIRST_DISCARDER = 1,
    EVENT_OPEN = EVENT_FIRST_DISCARDER,
    EVENT_MKDIR,
    EVENT_LINK,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_RMDIR,
    EVENT_CHMOD,
    EVENT_CHOWN,
    EVENT_UTIME,
    EVENT_SETXATTR,
    EVENT_REMOVEXATTR,
    EVENT_LAST_DISCARDER = EVENT_REMOVEXATTR,

    EVENT_MOUNT,
    EVENT_UMOUNT,
    EVENT_FORK,
    EVENT_EXEC,
    EVENT_EXIT,
    EVENT_INVALIDATE_DENTRY, // deprecated
    EVENT_SETUID,
    EVENT_SETGID,
    EVENT_CAPSET,
    EVENT_ARGS_ENVS,
    EVENT_MOUNT_RELEASED,
    EVENT_SELINUX,
    EVENT_BPF,
    EVENT_PTRACE,
    EVENT_MMAP,
    EVENT_MPROTECT,
    EVENT_INIT_MODULE,
    EVENT_DELETE_MODULE,
    EVENT_SIGNAL,
    EVENT_SPLICE,
    EVENT_CGROUP_TRACING,
    EVENT_DNS,
    EVENT_NET_DEVICE,
    EVENT_VETH_PAIR,
    EVENT_BIND,
    EVENT_UNSHARE_MNTNS,
    EVENT_SYSCALLS,
    EVENT_ANOMALY_DETECTION_SYSCALL,
    EVENT_MAX, // has to be the last one

    EVENT_ALL = 0xffffffff // used as a mask for all the events
};

#define EVENT_LAST_APPROVER EVENT_SPLICE

enum {
    EVENT_FLAGS_ASYNC = 1<<0, // async, mostly io_uring
    EVENT_FLAGS_SAVED_BY_AD = 1<<1, // event send because of activity dump
    EVENT_FLAGS_ACTIVITY_DUMP_SAMPLE = 1<<2, // event is a AD sample
};

enum file_flags {
    LOWER_LAYER = 1 << 0,
    UPPER_LAYER = 1 << 1,
};

enum {
    SYNC_SYSCALL = 0,
    ASYNC_SYSCALL
};

enum {
    ACTIVITY_DUMP_RUNNING = 1<<0, // defines if an activity dump is running
    SAVED_BY_ACTIVITY_DUMP = 1<<1, // defines if the dentry should have been discarded, but was saved because of an activity dump
};

enum policy_mode {
    NO_FILTER = 0,
    ACCEPT = 1,
    DENY = 2,
};

enum policy_flags {
    BASENAME = 1,
    FLAGS = 2,
    MODE = 4,
    PARENT_NAME = 8,
};

enum tls_format {
   DEFAULT_TLS_FORMAT
};

typedef enum discard_check_state {
    NOT_DISCARDED,
    DISCARDED,
} discard_check_state;

enum bpf_cmd_def {
    BPF_MAP_CREATE_CMD,
    BPF_MAP_LOOKUP_ELEM_CMD,
    BPF_MAP_UPDATE_ELEM_CMD,
    BPF_MAP_DELETE_ELEM_CMD,
    BPF_MAP_GET_NEXT_KEY_CMD,
    BPF_PROG_LOAD_CMD,
    BPF_OBJ_PIN_CMD,
    BPF_OBJ_GET_CMD,
    BPF_PROG_ATTACH_CMD,
    BPF_PROG_DETACH_CMD,
    BPF_PROG_TEST_RUN_CMD,
    BPF_PROG_GET_NEXT_ID_CMD,
    BPF_MAP_GET_NEXT_ID_CMD,
    BPF_PROG_GET_FD_BY_ID_CMD,
    BPF_MAP_GET_FD_BY_ID_CMD,
    BPF_OBJ_GET_INFO_BY_FD_CMD,
    BPF_PROG_QUERY_CMD,
    BPF_RAW_TRACEPOINT_OPEN_CMD,
    BPF_BTF_LOAD_CMD,
    BPF_BTF_GET_FD_BY_ID_CMD,
    BPF_TASK_FD_QUERY_CMD,
    BPF_MAP_LOOKUP_AND_DELETE_ELEM_CMD,
    BPF_MAP_FREEZE_CMD,
    BPF_BTF_GET_NEXT_ID_CMD,
    BPF_MAP_LOOKUP_BATCH_CMD,
    BPF_MAP_LOOKUP_AND_DELETE_BATCH_CMD,
    BPF_MAP_UPDATE_BATCH_CMD,
    BPF_MAP_DELETE_BATCH_CMD,
    BPF_LINK_CREATE_CMD,
    BPF_LINK_UPDATE_CMD,
    BPF_LINK_GET_FD_BY_ID_CMD,
    BPF_LINK_GET_NEXT_ID_CMD,
    BPF_ENABLE_STATS_CMD,
    BPF_ITER_CREATE_CMD,
    BPF_LINK_DETACH_CMD,
    BPF_PROG_BIND_MAP_CMD,
};

enum dr_progs_key {
    // prog keys used by tracepoint, kprobe and fentry prog types
    DR_NO_CALLBACK = 0,
    DR_ENTRYPOINT,
    DR_LOOP,
    DR_CALLBACK_OPEN,
    DR_CALLBACK_MKDIR,
    DR_CALLBACK_MOUNT,
    DR_CALLBACK_LINK_DST,
    DR_CALLBACK_RENAME_DST,
    // prog keys used by kprobe and fentry prog types
    DR_MAX_TRACEPOINT_PROGS,
    DR_CALLBACK_EXECUTABLE = DR_CALLBACK_RENAME_DST + 1,
    DR_CALLBACK_INTERPRETER,
    DR_CALLBACK_LINK_SRC,
    DR_CALLBACK_RENAME_SRC,
    DR_CALLBACK_RMDIR, // used by rmdir/unlink event types
    DR_CALLBACK_SELINUX,
    DR_CALLBACK_SETATTR, // used by chmod/chown/utimes event types
    DR_CALLBACK_SETXATTR, // used by setxattr/removexattr event types
    DR_CALLBACK_UNLINK,
    DR_CALLBACK_UNSHARE_MNTNS,
    DR_CALLBACK_INITMODULE,
    DR_MAX_KPROBE_AND_FENTRY_PROGS,
};

enum erpc_progs_key {
    ERPC_DR_RESOLVE_PARENT_DENTRY_KEY,
    ERPC_DR_RESOLVE_PATH_WATERMARK_READER_KEY,
    ERPC_DR_RESOLVE_PATH_DATA_READER_KEY,
    ERPC_MAX_PROGS,
};

enum erpc_op {
    UNKNOWN_OP,
    DISCARD_INODE_OP,
    DISCARD_PID_OP,
    RESOLVE_PARENT_DENTRY_OP,
    RESOLVE_PATHSEGMENT_OP,
    REGISTER_SPAN_TLS_OP, // can be used outside of the CWS, do not change the value
    EXPIRE_INODE_DISCARDER_OP,
    EXPIRE_PID_DISCARDER_OP,
    BUMP_DISCARDERS_REVISION,
    GET_RINGBUF_USAGE,
};

enum selinux_source_event_t {
    SELINUX_BOOL_CHANGE_SOURCE_EVENT,
    SELINUX_DISABLE_CHANGE_SOURCE_EVENT,
    SELINUX_ENFORCE_CHANGE_SOURCE_EVENT,
    SELINUX_BOOL_COMMIT_SOURCE_EVENT,
};

enum selinux_event_kind_t {
    SELINUX_BOOL_CHANGE_EVENT_KIND,
    SELINUX_STATUS_CHANGE_EVENT_KIND,
    SELINUX_BOOL_COMMIT_EVENT_KIND,
};

enum security_profile_state {
    SECURITY_PROFILE_UNKNOWN,
    SECURITY_PROFILE_ALERT,
    SECURITY_PROFILE_KILL,
};

#endif
