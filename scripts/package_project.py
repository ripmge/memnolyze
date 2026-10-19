"""Build a source ZIP with an explicitly selected demonstration case only."""
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = ('README.md', 'AGENTS.md', 'pyproject.toml', '.gitignore',
              'config.example.json', 'config.portable.json', 'examples/README.md')
TREES = {'src': {'.py'}, 'tests': {'.py'}, 'scripts': {'.py', '.ps1'},
         'docs': {'.md'}, 'examples/deep-case': {'.html', '.json', '.jsonl', '.txt', '.log'}}

def package() -> Path:
    selected = [ROOT / name for name in ROOT_FILES]
    for directory, extensions in TREES.items():
        selected.extend(path for path in (ROOT / directory).rglob('*')
                        if path.is_file() and not path.is_symlink() and
                        '__pycache__' not in path.parts and path.suffix in extensions)
    if not (ROOT / 'examples/deep-case/report.html').is_file():
        raise FileNotFoundError('The selected examples/deep-case report must be present')
    destination = ROOT / 'dist/memnolyze-source.zip'
    destination.parent.mkdir(exist_ok=True)
    with ZipFile(destination, 'w', compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(set(selected)):
            if not path.resolve().is_relative_to(ROOT):
                raise ValueError(f'Path outside project: {path}')
            archive.write(path, 'memnolyze/' + path.relative_to(ROOT).as_posix())
    with destination.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    destination.with_suffix('.zip.sha256').write_text(f'{digest}  {destination.name}\n', encoding='ascii')
    print(json.dumps({'archive': str(destination), 'files': len(set(selected)),
                      'bytes': destination.stat().st_size, 'sha256': digest}, indent=2))
    return destination

if __name__ == '__main__':
    package()
