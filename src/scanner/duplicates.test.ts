import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { compareVersions, findDuplicates, removeDuplicates } from './duplicates';

/** Build a throwaway extensions root so nothing touches a real editor install. */
function makeRoot(
  copies: Array<{ id: string; version: string; dirName?: string }>,
  opts: { obsolete?: string[]; active?: Record<string, string> } = {}
): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'extguard-dupes-'));
  for (const c of copies) {
    const [publisher, name] = c.id.split('.');
    const dirName = c.dirName ?? `${c.id}-${c.version}`;
    const dir = path.join(root, dirName);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ publisher, name, version: c.version }));
    fs.writeFileSync(path.join(dir, 'extension.js'), 'x'.repeat(1024));
  }
  if (opts.obsolete) {
    fs.writeFileSync(path.join(root, '.obsolete'), JSON.stringify(Object.fromEntries(opts.obsolete.map((d) => [d, true]))));
  }
  if (opts.active) {
    fs.writeFileSync(path.join(root, 'extensions.json'),
      JSON.stringify(Object.entries(opts.active).map(([id, version]) => ({ identifier: { id }, version }))));
  }
  return root;
}

describe('compareVersions', () => {
  it('orders numerically, not lexically', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBeGreaterThan(0);
    expect(compareVersions('2.1.234', '2.1.235')).toBeLessThan(0);
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
  });

  it('handles the mixed schemes real extensions actually ship', () => {
    // Observed on a real machine: openai.chatgpt carried both 0.4.55 and 26.5814.41407.
    expect(compareVersions('26.5814.41407', '0.4.55')).toBeGreaterThan(0);
    expect(compareVersions('1.2.3-win32-x64', '1.2.4-win32-x64')).toBeLessThan(0);
  });
});

describe('findDuplicates', () => {
  it('returns nothing when every extension has one copy', () => {
    const root = makeRoot([{ id: 'pub.a', version: '1.0.0' }, { id: 'pub.b', version: '2.0.0' }]);
    expect(findDuplicates(root)).toHaveLength(0);
  });

  it('keeps the highest version and proposes the rest', () => {
    const root = makeRoot([
      { id: 'pub.a', version: '1.0.0' },
      { id: 'pub.a', version: '1.2.0' },
      { id: 'pub.a', version: '1.1.0' },
    ]);
    const [group] = findDuplicates(root);
    expect(group.keep.version).toBe('1.2.0');
    expect(group.drop.map((d) => d.version).sort()).toEqual(['1.0.0', '1.1.0']);
    expect(group.reclaimableBytes).toBeGreaterThan(0);
  });

  it('defers to extensions.json when it disagrees with version order', () => {
    // The editor is the authority on what it actually loads. Deleting the live copy because
    // a version string looked higher would break a working extension.
    const root = makeRoot(
      [{ id: 'pub.a', version: '1.0.0' }, { id: 'pub.a', version: '2.0.0' }],
      { active: { 'pub.a': '1.0.0' } }
    );
    const [group] = findDuplicates(root);
    expect(group.keep.version).toBe('1.0.0');
    expect(group.drop.map((d) => d.version)).toEqual(['2.0.0']);
  });

  it('marks copies the editor listed in .obsolete', () => {
    const root = makeRoot(
      [{ id: 'pub.a', version: '1.0.0', dirName: 'pub.a-1.0.0' }, { id: 'pub.a', version: '2.0.0' }],
      { obsolete: ['pub.a-1.0.0'] }
    );
    const [group] = findDuplicates(root);
    expect(group.drop[0].obsolete).toBe(true);
  });

  it('ignores a directory with no package.json', () => {
    const root = makeRoot([{ id: 'pub.a', version: '1.0.0' }]);
    fs.mkdirSync(path.join(root, 'junk-directory'));
    expect(findDuplicates(root)).toHaveLength(0);
  });

  it('returns nothing for a root that does not exist', () => {
    expect(findDuplicates(path.join(os.tmpdir(), 'extguard-definitely-missing'))).toHaveLength(0);
  });
});

describe('removeDuplicates', () => {
  it('never deletes a copy the running editor has not released', () => {
    const root = makeRoot([{ id: 'pub.a', version: '1.0.0' }, { id: 'pub.a', version: '2.0.0' }]);
    const groups = findDuplicates(root);
    const result = removeDuplicates(groups, { editorRunning: true });
    expect(result.removed).toHaveLength(0);
    expect(result.skipped).toHaveLength(1);
    expect(fs.existsSync(groups[0].drop[0].dir)).toBe(true);
  });

  it('deletes obsolete copies even while the editor runs, since it released them', () => {
    const root = makeRoot(
      [{ id: 'pub.a', version: '1.0.0', dirName: 'pub.a-1.0.0' }, { id: 'pub.a', version: '2.0.0' }],
      { obsolete: ['pub.a-1.0.0'] }
    );
    const groups = findDuplicates(root);
    const result = removeDuplicates(groups, { editorRunning: true });
    expect(result.removed).toHaveLength(1);
    expect(result.bytesReclaimed).toBeGreaterThan(0);
    expect(fs.existsSync(groups[0].drop[0].dir)).toBe(false);
  });

  it('never touches the kept version', () => {
    const root = makeRoot(
      [{ id: 'pub.a', version: '1.0.0', dirName: 'pub.a-1.0.0' }, { id: 'pub.a', version: '2.0.0' }],
      { obsolete: ['pub.a-1.0.0'] }
    );
    const groups = findDuplicates(root);
    removeDuplicates(groups, { editorRunning: false });
    expect(fs.existsSync(groups[0].keep.dir)).toBe(true);
  });
});
