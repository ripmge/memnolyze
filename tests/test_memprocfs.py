"""Native-worker failure-policy tests with an explicitly synthetic API object."""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from memnolyze.backends.memprocfs import worker
from memnolyze.config import load_config
from memnolyze.io import write_json, read_json

class WorkerTests(unittest.TestCase):
    def test_incomplete_forensic_results_are_not_exported_and_vmm_is_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configs = load_config(None)
            configs['forensic_timeout_seconds'] = 1
            job = root / 'job.json'
            write_json(job, {'config': configs, 'target': str(root), 'image': 'test-only.raw',
                             'offline': True, 'pid': None, 'profile': 'quick'})
            closed = []
            arguments = []
            class Vmm:
                def __init__(self, args):
                    arguments.extend(args)
                    self.maps = types.SimpleNamespace(net=lambda: [])
                    self.vfs = types.SimpleNamespace(read=lambda *args: b'99')
                def get_config(self, key):
                    return {'system': 2, 'build': 17134, 'MAJOR': 5, 'MINOR': 19, 'REVISION': 0}[key]
                def process_list(self):
                    return []
                def close(self):
                    closed.append(True)
            module = types.SimpleNamespace(Vmm=Vmm, OPT_CORE_SYSTEM='system', OPT_WIN_VERSION_BUILD='build',
                                            SYSTEM_WINDOWS_X64=2, SYSTEM_WINDOWS_X86=4,
                                            OPT_CONFIG_VMM_VERSION_MAJOR='MAJOR',
                                            OPT_CONFIG_VMM_VERSION_MINOR='MINOR',
                                            OPT_CONFIG_VMM_VERSION_REVISION='REVISION')
            with patch.dict(sys.modules, memprocfs=module), \
                 patch('memnolyze.backends.memprocfs.time.monotonic', side_effect=[0, 2]):
                with self.assertRaises(TimeoutError):
                    worker(job)
            self.assertEqual(closed, [True])
            self.assertFalse((root / 'findevil.txt').exists())
            self.assertEqual(read_json(root / 'info.json')['windows_build'], 17134)
            self.assertIn('-disable-symbolserver', arguments)
            self.assertIn('-disable-python', arguments)
            self.assertIn('-disable-yara', arguments)
            self.assertNotIn('-license-accept-elastic-license-2-0', arguments)
