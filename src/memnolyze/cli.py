"""Public CLI. JSON configuration keeps the runtime dependency-free."""
import argparse
import json
import logging
import sys
from pathlib import Path
from .config import load_config, PROFILES
from .backends import volatility, memprocfs

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='memnolyze')
    sub = parser.add_subparsers(dest='action', required=True)
    doctor = sub.add_parser('doctor', help='Discover tools and installed plugin capabilities')
    doctor.add_argument('--config', type=Path)
    analyze = sub.add_parser('analyze', help='Analyze a local image; network access disabled by default')
    analyze.add_argument('--image', type=Path, required=True)
    analyze.add_argument('--output', type=Path, required=True)
    analyze.add_argument('--profile', choices=PROFILES, default='quick')
    analyze.add_argument('--backend', choices=['volatility', 'memprocfs', 'all'], default='all')
    analyze.add_argument('--pid', type=int)
    analyze.add_argument('--config', type=Path)
    analyze.add_argument('--resume', action='store_true')
    network = analyze.add_mutually_exclusive_group()
    network.add_argument('--offline', dest='offline', action='store_true', default=True)
    network.add_argument('--allow-symbol-downloads', dest='offline', action='store_false')
    analyze.add_argument('--plugin', action='append', help='Run selected logical Volatility plugin(s), plus info')
    analyze.add_argument('--rerun', action='append', default=[],
                         help='Explicitly rerun a completed logical plugin, or triage for MemProcFS; retains old raw attempts')
    analyze.add_argument('--verbose', action='store_true')
    report = sub.add_parser('report', help='Rebuild HTML from normalized case artifacts')
    report.add_argument('--case', type=Path, required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    try:
        if args.action == 'report':
            from .reporting import render
            render(args.case)
            print(args.case.resolve() / 'report.html')
            return 0
        config = load_config(args.config)
        if args.action == 'doctor':
            print(json.dumps({'python': sys.version, 'volatility': volatility.discover(config),
                              'memprocfs': memprocfs.discover(config)}, indent=2))
            return 0
        if args.pid is not None and args.pid < 0:
            raise ValueError('PID must be nonnegative')
        from .pipeline import analyze as run
        return run(args.image, args.output, config, args.profile, args.backend, args.offline,
                   args.resume, args.pid, args.plugin, args.rerun)
    except (OSError, ValueError) as exc:
        logging.error('%s', exc)
        return 1
