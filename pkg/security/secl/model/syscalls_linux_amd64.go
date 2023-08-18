// Code generated - DO NOT EDIT.
// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package model

// Syscall represents a syscall identifier
type Syscall int

// Linux syscall identifiers
const (
	SysRead                  Syscall = 0
	SysWrite                 Syscall = 1
	SysOpen                  Syscall = 2
	SysClose                 Syscall = 3
	SysStat                  Syscall = 4
	SysFstat                 Syscall = 5
	SysLstat                 Syscall = 6
	SysPoll                  Syscall = 7
	SysLseek                 Syscall = 8
	SysMmap                  Syscall = 9
	SysMprotect              Syscall = 10
	SysMunmap                Syscall = 11
	SysBrk                   Syscall = 12
	SysRtSigaction           Syscall = 13
	SysRtSigprocmask         Syscall = 14
	SysRtSigreturn           Syscall = 15
	SysIoctl                 Syscall = 16
	SysPread64               Syscall = 17
	SysPwrite64              Syscall = 18
	SysReadv                 Syscall = 19
	SysWritev                Syscall = 20
	SysAccess                Syscall = 21
	SysPipe                  Syscall = 22
	SysSelect                Syscall = 23
	SysSchedYield            Syscall = 24
	SysMremap                Syscall = 25
	SysMsync                 Syscall = 26
	SysMincore               Syscall = 27
	SysMadvise               Syscall = 28
	SysShmget                Syscall = 29
	SysShmat                 Syscall = 30
	SysShmctl                Syscall = 31
	SysDup                   Syscall = 32
	SysDup2                  Syscall = 33
	SysPause                 Syscall = 34
	SysNanosleep             Syscall = 35
	SysGetitimer             Syscall = 36
	SysAlarm                 Syscall = 37
	SysSetitimer             Syscall = 38
	SysGetpid                Syscall = 39
	SysSendfile              Syscall = 40
	SysSocket                Syscall = 41
	SysConnect               Syscall = 42
	SysAccept                Syscall = 43
	SysSendto                Syscall = 44
	SysRecvfrom              Syscall = 45
	SysSendmsg               Syscall = 46
	SysRecvmsg               Syscall = 47
	SysShutdown              Syscall = 48
	SysBind                  Syscall = 49
	SysListen                Syscall = 50
	SysGetsockname           Syscall = 51
	SysGetpeername           Syscall = 52
	SysSocketpair            Syscall = 53
	SysSetsockopt            Syscall = 54
	SysGetsockopt            Syscall = 55
	SysClone                 Syscall = 56
	SysFork                  Syscall = 57
	SysVfork                 Syscall = 58
	SysExecve                Syscall = 59
	SysExit                  Syscall = 60
	SysWait4                 Syscall = 61
	SysKill                  Syscall = 62
	SysUname                 Syscall = 63
	SysSemget                Syscall = 64
	SysSemop                 Syscall = 65
	SysSemctl                Syscall = 66
	SysShmdt                 Syscall = 67
	SysMsgget                Syscall = 68
	SysMsgsnd                Syscall = 69
	SysMsgrcv                Syscall = 70
	SysMsgctl                Syscall = 71
	SysFcntl                 Syscall = 72
	SysFlock                 Syscall = 73
	SysFsync                 Syscall = 74
	SysFdatasync             Syscall = 75
	SysTruncate              Syscall = 76
	SysFtruncate             Syscall = 77
	SysGetdents              Syscall = 78
	SysGetcwd                Syscall = 79
	SysChdir                 Syscall = 80
	SysFchdir                Syscall = 81
	SysRename                Syscall = 82
	SysMkdir                 Syscall = 83
	SysRmdir                 Syscall = 84
	SysCreat                 Syscall = 85
	SysLink                  Syscall = 86
	SysUnlink                Syscall = 87
	SysSymlink               Syscall = 88
	SysReadlink              Syscall = 89
	SysChmod                 Syscall = 90
	SysFchmod                Syscall = 91
	SysChown                 Syscall = 92
	SysFchown                Syscall = 93
	SysLchown                Syscall = 94
	SysUmask                 Syscall = 95
	SysGettimeofday          Syscall = 96
	SysGetrlimit             Syscall = 97
	SysGetrusage             Syscall = 98
	SysSysinfo               Syscall = 99
	SysTimes                 Syscall = 100
	SysPtrace                Syscall = 101
	SysGetuid                Syscall = 102
	SysSyslog                Syscall = 103
	SysGetgid                Syscall = 104
	SysSetuid                Syscall = 105
	SysSetgid                Syscall = 106
	SysGeteuid               Syscall = 107
	SysGetegid               Syscall = 108
	SysSetpgid               Syscall = 109
	SysGetppid               Syscall = 110
	SysGetpgrp               Syscall = 111
	SysSetsid                Syscall = 112
	SysSetreuid              Syscall = 113
	SysSetregid              Syscall = 114
	SysGetgroups             Syscall = 115
	SysSetgroups             Syscall = 116
	SysSetresuid             Syscall = 117
	SysGetresuid             Syscall = 118
	SysSetresgid             Syscall = 119
	SysGetresgid             Syscall = 120
	SysGetpgid               Syscall = 121
	SysSetfsuid              Syscall = 122
	SysSetfsgid              Syscall = 123
	SysGetsid                Syscall = 124
	SysCapget                Syscall = 125
	SysCapset                Syscall = 126
	SysRtSigpending          Syscall = 127
	SysRtSigtimedwait        Syscall = 128
	SysRtSigqueueinfo        Syscall = 129
	SysRtSigsuspend          Syscall = 130
	SysSigaltstack           Syscall = 131
	SysUtime                 Syscall = 132
	SysMknod                 Syscall = 133
	SysUselib                Syscall = 134
	SysPersonality           Syscall = 135
	SysUstat                 Syscall = 136
	SysStatfs                Syscall = 137
	SysFstatfs               Syscall = 138
	SysSysfs                 Syscall = 139
	SysGetpriority           Syscall = 140
	SysSetpriority           Syscall = 141
	SysSchedSetparam         Syscall = 142
	SysSchedGetparam         Syscall = 143
	SysSchedSetscheduler     Syscall = 144
	SysSchedGetscheduler     Syscall = 145
	SysSchedGetPriorityMax   Syscall = 146
	SysSchedGetPriorityMin   Syscall = 147
	SysSchedRrGetInterval    Syscall = 148
	SysMlock                 Syscall = 149
	SysMunlock               Syscall = 150
	SysMlockall              Syscall = 151
	SysMunlockall            Syscall = 152
	SysVhangup               Syscall = 153
	SysModifyLdt             Syscall = 154
	SysPivotRoot             Syscall = 155
	SysSysctl                Syscall = 156
	SysPrctl                 Syscall = 157
	SysArchPrctl             Syscall = 158
	SysAdjtimex              Syscall = 159
	SysSetrlimit             Syscall = 160
	SysChroot                Syscall = 161
	SysSync                  Syscall = 162
	SysAcct                  Syscall = 163
	SysSettimeofday          Syscall = 164
	SysMount                 Syscall = 165
	SysUmount2               Syscall = 166
	SysSwapon                Syscall = 167
	SysSwapoff               Syscall = 168
	SysReboot                Syscall = 169
	SysSethostname           Syscall = 170
	SysSetdomainname         Syscall = 171
	SysIopl                  Syscall = 172
	SysIoperm                Syscall = 173
	SysCreateModule          Syscall = 174
	SysInitModule            Syscall = 175
	SysDeleteModule          Syscall = 176
	SysGetKernelSyms         Syscall = 177
	SysQueryModule           Syscall = 178
	SysQuotactl              Syscall = 179
	SysNfsservctl            Syscall = 180
	SysGetpmsg               Syscall = 181
	SysPutpmsg               Syscall = 182
	SysAfsSyscall            Syscall = 183
	SysTuxcall               Syscall = 184
	SysSecurity              Syscall = 185
	SysGettid                Syscall = 186
	SysReadahead             Syscall = 187
	SysSetxattr              Syscall = 188
	SysLsetxattr             Syscall = 189
	SysFsetxattr             Syscall = 190
	SysGetxattr              Syscall = 191
	SysLgetxattr             Syscall = 192
	SysFgetxattr             Syscall = 193
	SysListxattr             Syscall = 194
	SysLlistxattr            Syscall = 195
	SysFlistxattr            Syscall = 196
	SysRemovexattr           Syscall = 197
	SysLremovexattr          Syscall = 198
	SysFremovexattr          Syscall = 199
	SysTkill                 Syscall = 200
	SysTime                  Syscall = 201
	SysFutex                 Syscall = 202
	SysSchedSetaffinity      Syscall = 203
	SysSchedGetaffinity      Syscall = 204
	SysSetThreadArea         Syscall = 205
	SysIoSetup               Syscall = 206
	SysIoDestroy             Syscall = 207
	SysIoGetevents           Syscall = 208
	SysIoSubmit              Syscall = 209
	SysIoCancel              Syscall = 210
	SysGetThreadArea         Syscall = 211
	SysLookupDcookie         Syscall = 212
	SysEpollCreate           Syscall = 213
	SysEpollCtlOld           Syscall = 214
	SysEpollWaitOld          Syscall = 215
	SysRemapFilePages        Syscall = 216
	SysGetdents64            Syscall = 217
	SysSetTidAddress         Syscall = 218
	SysRestartSyscall        Syscall = 219
	SysSemtimedop            Syscall = 220
	SysFadvise64             Syscall = 221
	SysTimerCreate           Syscall = 222
	SysTimerSettime          Syscall = 223
	SysTimerGettime          Syscall = 224
	SysTimerGetoverrun       Syscall = 225
	SysTimerDelete           Syscall = 226
	SysClockSettime          Syscall = 227
	SysClockGettime          Syscall = 228
	SysClockGetres           Syscall = 229
	SysClockNanosleep        Syscall = 230
	SysExitGroup             Syscall = 231
	SysEpollWait             Syscall = 232
	SysEpollCtl              Syscall = 233
	SysTgkill                Syscall = 234
	SysUtimes                Syscall = 235
	SysVserver               Syscall = 236
	SysMbind                 Syscall = 237
	SysSetMempolicy          Syscall = 238
	SysGetMempolicy          Syscall = 239
	SysMqOpen                Syscall = 240
	SysMqUnlink              Syscall = 241
	SysMqTimedsend           Syscall = 242
	SysMqTimedreceive        Syscall = 243
	SysMqNotify              Syscall = 244
	SysMqGetsetattr          Syscall = 245
	SysKexecLoad             Syscall = 246
	SysWaitid                Syscall = 247
	SysAddKey                Syscall = 248
	SysRequestKey            Syscall = 249
	SysKeyctl                Syscall = 250
	SysIoprioSet             Syscall = 251
	SysIoprioGet             Syscall = 252
	SysInotifyInit           Syscall = 253
	SysInotifyAddWatch       Syscall = 254
	SysInotifyRmWatch        Syscall = 255
	SysMigratePages          Syscall = 256
	SysOpenat                Syscall = 257
	SysMkdirat               Syscall = 258
	SysMknodat               Syscall = 259
	SysFchownat              Syscall = 260
	SysFutimesat             Syscall = 261
	SysNewfstatat            Syscall = 262
	SysUnlinkat              Syscall = 263
	SysRenameat              Syscall = 264
	SysLinkat                Syscall = 265
	SysSymlinkat             Syscall = 266
	SysReadlinkat            Syscall = 267
	SysFchmodat              Syscall = 268
	SysFaccessat             Syscall = 269
	SysPselect6              Syscall = 270
	SysPpoll                 Syscall = 271
	SysUnshare               Syscall = 272
	SysSetRobustList         Syscall = 273
	SysGetRobustList         Syscall = 274
	SysSplice                Syscall = 275
	SysTee                   Syscall = 276
	SysSyncFileRange         Syscall = 277
	SysVmsplice              Syscall = 278
	SysMovePages             Syscall = 279
	SysUtimensat             Syscall = 280
	SysEpollPwait            Syscall = 281
	SysSignalfd              Syscall = 282
	SysTimerfdCreate         Syscall = 283
	SysEventfd               Syscall = 284
	SysFallocate             Syscall = 285
	SysTimerfdSettime        Syscall = 286
	SysTimerfdGettime        Syscall = 287
	SysAccept4               Syscall = 288
	SysSignalfd4             Syscall = 289
	SysEventfd2              Syscall = 290
	SysEpollCreate1          Syscall = 291
	SysDup3                  Syscall = 292
	SysPipe2                 Syscall = 293
	SysInotifyInit1          Syscall = 294
	SysPreadv                Syscall = 295
	SysPwritev               Syscall = 296
	SysRtTgsigqueueinfo      Syscall = 297
	SysPerfEventOpen         Syscall = 298
	SysRecvmmsg              Syscall = 299
	SysFanotifyInit          Syscall = 300
	SysFanotifyMark          Syscall = 301
	SysPrlimit64             Syscall = 302
	SysNameToHandleAt        Syscall = 303
	SysOpenByHandleAt        Syscall = 304
	SysClockAdjtime          Syscall = 305
	SysSyncfs                Syscall = 306
	SysSendmmsg              Syscall = 307
	SysSetns                 Syscall = 308
	SysGetcpu                Syscall = 309
	SysProcessVmReadv        Syscall = 310
	SysProcessVmWritev       Syscall = 311
	SysKcmp                  Syscall = 312
	SysFinitModule           Syscall = 313
	SysSchedSetattr          Syscall = 314
	SysSchedGetattr          Syscall = 315
	SysRenameat2             Syscall = 316
	SysSeccomp               Syscall = 317
	SysGetrandom             Syscall = 318
	SysMemfdCreate           Syscall = 319
	SysKexecFileLoad         Syscall = 320
	SysBpf                   Syscall = 321
	SysExecveat              Syscall = 322
	SysUserfaultfd           Syscall = 323
	SysMembarrier            Syscall = 324
	SysMlock2                Syscall = 325
	SysCopyFileRange         Syscall = 326
	SysPreadv2               Syscall = 327
	SysPwritev2              Syscall = 328
	SysPkeyMprotect          Syscall = 329
	SysPkeyAlloc             Syscall = 330
	SysPkeyFree              Syscall = 331
	SysStatx                 Syscall = 332
	SysIoPgetevents          Syscall = 333
	SysRseq                  Syscall = 334
	SysPidfdSendSignal       Syscall = 424
	SysIoUringSetup          Syscall = 425
	SysIoUringEnter          Syscall = 426
	SysIoUringRegister       Syscall = 427
	SysOpenTree              Syscall = 428
	SysMoveMount             Syscall = 429
	SysFsopen                Syscall = 430
	SysFsconfig              Syscall = 431
	SysFsmount               Syscall = 432
	SysFspick                Syscall = 433
	SysPidfdOpen             Syscall = 434
	SysClone3                Syscall = 435
	SysCloseRange            Syscall = 436
	SysOpenat2               Syscall = 437
	SysPidfdGetfd            Syscall = 438
	SysFaccessat2            Syscall = 439
	SysProcessMadvise        Syscall = 440
	SysEpollPwait2           Syscall = 441
	SysMountSetattr          Syscall = 442
	SysQuotactlFd            Syscall = 443
	SysLandlockCreateRuleset Syscall = 444
	SysLandlockAddRule       Syscall = 445
	SysLandlockRestrictSelf  Syscall = 446
	SysMemfdSecret           Syscall = 447
	SysProcessMrelease       Syscall = 448
	SysFutexWaitv            Syscall = 449
	SysSetMempolicyHomeNode  Syscall = 450
)
