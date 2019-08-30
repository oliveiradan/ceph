import abc
from abc import ABC, abstractmethod
from contextlib import contextmanager
from mgr_module import MgrModule, CLIReadCommand, CLIWriteCommand
from threading import Event
try:
    import queue as Queue
except ImportError:
    import Queue

'''
{
  "_snap_policy": {
    "_snap_policy_id": "e164a2a6-129c-4852-9ec8-8a2101ea4e44",
    "_snap_policy_name": "Snapshot_Template1",
    "_snap_policy_info": "Snapshots for: M, W, F @10pm on HostX/SubvolumeY",
    "_snap_policy_usedby": {
      "0c973a4b-284d-40dc-8c54-5df862d13539"
    },
    "_snap_policy_schedule": {
      "_snap_runs": {
        "_minutes": "00",
        "_hours": "00",
        "_days": "00",
        "_weeks": "00",
        "_months": "00",
        "_years": "2019",
        "_last": "00",
        "_within": "00"
      }
    }
  },
  "_prune_policy": {
    "_prune_policy_id": "56b00e1f-102a-492a-a2f4-6940ebf7ac3b",
    "_prune_policy_name": "Prune_Template1",
    "_prune_policy_info": "Prunes for: M, W, F @10:30pm on HostX/SubvolumeY",
    "_prune_policy_usedby": {
      "0c973a4b-284d-40dc-8c54-5df862d13539"
    },
    "_prune_policy_schedule": {
      "_prune_runs": {
        "_minutes": "00",
        "_hours": "00",
        "_days": "00",
        "_weeks": "00",
        "_months": "00",
        "_years": "2019",
        "_last": "00",
        "_within": "00"
      }
    }
  },
  "cephfs_scheduler": {
    "_cephfs_sched_id": "0c973a4b-284d-40dc-8c54-5df862d13539",
    "_hostname": "",
    "_path": "",
    "_subvolume": "",
    "_snap_policies": {
      "e164a2a6-129c-4852-9ec8-8a2101ea4e44"
    },
    "_prune_policies": {
      "56b00e1f-102a-492a-a2f4-6940ebf7ac3b"
    }
  }
}
'''


class cephfs_policy(object):

    class cephfs_policy_schedule(object):

        def __init__(self):
            self.minutes = 0
            self.hours   = 0
            self.days    = 0
            self.weeks   = 0
            self.months  = 0
            self.years   = 0
            self.last    = 0
            self.within  = 0


    def __init__(self, policy_id, policy_name):
        self.policy_id          = policy_id
        self.policy_name        = policy_name
        self.policy_info        = ""
        self.policy_schedule    = self.cephfs_policy_schedule
        self._policy_usedby     = {}


class cephfs_snap_policy(cephfs_policy):
    def __init__(self, snap_policy_id, snap_policy_name):
        super().__init__(snap_policy_id, snap_policy_name)
        pass


class cephfs_prune_policy(cephfs_policy):
    def __init__(self, pruner_policy_id, pruner_policy_name):
        super().__init__(pruner_policy_id, pruner_policy_name)
        pass

class cephfs_scheduler(object):
    def __init__(self, schedule_id, subvolume):
        self.schedule_id    = schedule_id
        self.hostname       = ""
        self.path           = ""
        self.subvolume      = subvolume
        self.snap_policies  = {}
        self.prune_policies = {}


class Module(MgrModule):

    MODULE_OPTIONS = [{},{},]
    COMMANDS = [{"cmd": "fs snap-schedule set=snapname,type=CephString...",},{},]

    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)
        self.event = Event()
