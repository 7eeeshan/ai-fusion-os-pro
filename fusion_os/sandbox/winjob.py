"""Windows Job Object confinement for process-sandbox children (Windows only; imported lazily).

The child is created suspended, put in a job, then resumed, so it never runs a single instruction outside the job.
The job caps committed memory, allows one active process (no children), kills everything when the job handle is
closed, disables the Windows error dialog, and blocks desktop, clipboard, global atom and system-setting access.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000

_JobObjectBasicUIRestrictions = 4
_JobObjectExtendedLimitInformation = 9
_LIMIT_PROCESS_MEMORY = 0x00000100
_LIMIT_ACTIVE_PROCESS = 0x00000008
_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_LIMIT_PROCESS_TIME = 0x00000002
_UILIMIT_ALL = 0x000000FF  # handles, read/write clipboard, system parameters, display settings, global atoms, desktop, exit windows


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                  "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class _EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def _check(ok) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def confine(popen, memory_mb: int, timeout_s: float):
    """Put a suspended child into a new job with limits, then resume it. Returns the job handle."""
    k = _k32()
    job = k.CreateJobObjectW(None, None)
    _check(job)
    try:
        info = _EXTENDED_LIMIT()
        b = info.BasicLimitInformation
        b.LimitFlags = (_LIMIT_PROCESS_MEMORY | _LIMIT_ACTIVE_PROCESS | _LIMIT_KILL_ON_JOB_CLOSE
                        | _LIMIT_DIE_ON_UNHANDLED_EXCEPTION | _LIMIT_PROCESS_TIME)
        b.ActiveProcessLimit = 1
        b.PerProcessUserTimeLimit = int((timeout_s + 1) * 10_000_000)  # 100 ns units of CPU time
        info.ProcessMemoryLimit = memory_mb * 1024 * 1024
        _check(k.SetInformationJobObject(job, _JobObjectExtendedLimitInformation, ctypes.byref(info),
                                         ctypes.sizeof(info)))
        ui = _UI_RESTRICTIONS(_UILIMIT_ALL)
        _check(k.SetInformationJobObject(job, _JobObjectBasicUIRestrictions, ctypes.byref(ui), ctypes.sizeof(ui)))
        _check(k.AssignProcessToJobObject(job, wintypes.HANDLE(int(popen._handle))))
        nt = ctypes.WinDLL("ntdll")
        nt.NtResumeProcess.argtypes = [wintypes.HANDLE]
        if nt.NtResumeProcess(wintypes.HANDLE(int(popen._handle))) != 0:
            raise OSError("NtResumeProcess failed")
        return job
    except Exception:
        k.TerminateJobObject(job, 1)
        k.CloseHandle(job)
        raise


def terminate(job) -> None:
    _k32().TerminateJobObject(job, 1)


def close(job) -> None:
    _k32().CloseHandle(job)


def kill_with_parent(popen):
    """Put an already running helper (e.g. tor.exe) in a job that dies when this process exits. Returns the job;
    keep a reference to it for as long as the helper should live."""
    k = _k32()
    job = k.CreateJobObjectW(None, None)
    _check(job)
    info = _EXTENDED_LIMIT()
    info.BasicLimitInformation.LimitFlags = _LIMIT_KILL_ON_JOB_CLOSE | _LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    _check(k.SetInformationJobObject(job, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)))
    _check(k.AssignProcessToJobObject(job, wintypes.HANDLE(int(popen._handle))))
    return job
