#!/usr/bin/env python3
"""Every crate a workflow watches must have its whole graph watched too.

A `paths:` filter decides whether a workflow runs at all. If it names a crate
but not what that crate is built and tested from, a change to a dependency
skips the job that would have caught it -- and the pull request goes green
having tested nothing of the kind. #302 is the bill: `portal.yml` named
`isekai-p2p-core` but not `channel-masque`, the H3 transport underneath it, so
a fix to nothing but that crate ran no portal job at all.

So the rule checked here is closure, not a list anybody has to remember: if a
filter watches a crate, it must watch every local crate in that crate's
dependency graph, plus the manifest and lockfile its versions are resolved
through. Nothing here says which crates a workflow *should* watch -- that is
the author's call, and a deliberately narrow filter stays narrow -- only that
whatever is watched is watched completely.

The graph comes from `cargo metadata`, run once per workspace root in the
tree, so it includes workspace-inherited dependencies (`h3-util` reaches
`channel-masque` through `rust/Cargo.toml`, not through its own manifest) and
the second workspace under `rust/portal-client-ffi`, which Gradle builds and
no `-p` flag in any workflow would reveal.

**Dev- and build-dependencies count.** The rule says "built and tested from"
because the jobs being gated run `cargo test`, and a dev-dependency change
breaks that as surely as a normal one. This makes the closure wider than a
pure build graph, which is the safe direction: the cost of a wrong answer here
is a job that runs when it need not, against a job that does not run when it
must.

Run it from anywhere. Exits non-zero, naming each path to add, when a filter
is not closed.
"""

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def cargo_metadata(directory):
    """`cargo metadata` in `directory`, with cargo's own message on failure.

    Relayed rather than swallowed: without this a partly-failed submodule
    checkout or an unreachable registry surfaces as a bare `CalledProcessError`
    showing the argv and an exit code, and the line that says what went wrong
    -- `failed to load manifest for workspace member ...` -- is thrown away.
    """
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=directory,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(f"cargo metadata failed in {directory}:\n{result.stderr}")
        sys.exit(2)
    return json.loads(result.stdout)


def watch_path(directory):
    """The path a filter would name for a package living in `directory`.

    Submodules are watched whole -- the workflows name `submodules/tonic-h3`,
    never the crate inside it -- because that is the unit a submodule bump
    moves.
    """
    parts = directory.split("/")
    if parts[0] == "submodules":
        return "/".join(parts[:2])
    return directory


def graph():
    """`{crate: (watch path, {dependencies}, {resolved-through paths})}`.

    The third set is the workspace manifest and lockfile of every workspace
    this crate is a *member* of -- where its dependency versions actually come
    from. Path dependencies that are not members contribute none, because the
    directory they live in is watched whole anyway.
    """
    packages = {}
    # **`git ls-files`, not a filesystem walk.** A submodule's contents are not
    # tracked here, so this finds this repository's own workspaces -- `rust`
    # and `rust/portal-client-ffi` -- and not the several inside
    # `msquic-async-rs` and `tonic-h3`, whose manifests no filter should be
    # asked to name: the submodule is watched whole, as one gitlink entry.
    tracked = subprocess.run(
        ["git", "ls-files", "*Cargo.toml"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    for relative_manifest in sorted(tracked):
        manifest = ROOT / relative_manifest
        if "[workspace]" not in manifest.read_text():
            continue
        meta = cargo_metadata(manifest.parent)
        root = Path(meta["workspace_root"]).resolve().relative_to(ROOT).as_posix()
        members = set(meta["workspace_members"])
        for package in meta["packages"]:
            # `source` is null for a path dependency, which is exactly the set
            # a `paths:` filter can watch. Registry crates are someone else's.
            if package.get("source") is not None:
                continue
            directory = Path(package["manifest_path"]).resolve().parent
            try:
                relative = directory.relative_to(ROOT).as_posix()
            except ValueError:
                continue
            name = package["name"]
            entry = packages.setdefault(name, (watch_path(relative), set(), set()))
            entry[1].update(d["name"] for d in package["dependencies"])
            if package["id"] in members:
                # Through `watch_path` like any other: a workspace root inside
                # a submodule would be covered by the submodule's own entry,
                # never by naming its manifest.
                where = watch_path(root)
                if where == root:
                    entry[2].update({f"{root}/Cargo.toml", f"{root}/Cargo.lock"})
                else:
                    entry[2].add(where)
    # Narrowed last, so an edge is kept whichever workspace revealed it.
    return {
        name: (path, {d for d in deps if d in packages}, resolved)
        for name, (path, deps, resolved) in packages.items()
    }


def closure(name, packages):
    seen, stack = {name}, [name]
    while stack:
        for dependency in packages[stack.pop()][1]:
            if dependency not in seen:
                seen.add(dependency)
                stack.append(dependency)
    return seen


def matches(entry, path):
    """Does a filter entry watch the package living at `path`?

    **Globs are resolved, not compared as text.** An earlier version only
    looked for an exact entry, so `rust/**` matched no package and the two
    workflows that watch the tree that way were not checked at all --
    `mutants.yml`, one of the two, was the one with a gap.

    **A submodule is not watched by a glob rooted at it.** `submodules/tonic-h3`
    is a single gitlink entry in this repository, so `submodules/tonic-h3/**`
    matches only things *under* a path that has nothing under it, and never the
    pointer moving, which is the one change to it a pull request can carry. A
    glob further up (`submodules/**`) does match it, and `camera-apps.yml`
    relies on that.
    """
    submodule = path.startswith("submodules/")
    if entry == path or (entry == path + "/**" and not submodule):
        return True
    if not entry.endswith("**"):
        return False
    prefix = entry[:-2]
    if submodule and len(prefix) >= len(path) + 1:
        return False
    return (path + "/").startswith(prefix)


def covers(listed, path):
    return any(matches(entry, path) for entry in listed)


def filters(text):
    """Each `paths:` block in a workflow, as `(trigger, {entries})`.

    **Parsed as YAML, not with a regex.** Hand-matching `- '...'` lines missed
    every other legal spelling -- double quotes, a bare scalar, an inline
    `['...']` -- and a filter it could not read came out as the empty set,
    which read as closed. One unrecognized line mid-block also truncated the
    rest while grading the remainder, inventing failures for paths listed two
    lines below.

    **One block at a time, never the union of them.** A workflow lists its
    paths once per trigger, and reading the whole `on:` section together meant
    dropping a crate from `push` while `pull_request` still named it read as
    closed. `portal.yml`'s `push` filter is what gates the release job on a
    tag, so a gap on one trigger and not the other is a live failure.

    `paths-ignore` is returned separately, and deliberately not graded: the
    closure rule does not invert. Ignoring a crate implies nothing about
    ignoring its dependencies, and grading it as if it did would have demanded
    that `channel-masque` and both submodules be *added to the ignore list* --
    the exact gap this exists to prevent.
    """
    document = yaml.safe_load(text)
    # YAML 1.1 reads a bare `on` as the boolean true, which is why the key is
    # looked up both ways.
    triggers = document.get(True, document.get("on"))
    if not isinstance(triggers, dict):
        return [], []
    graded, ignored = [], []
    for trigger, config in triggers.items():
        if not isinstance(config, dict):
            continue
        if config.get("paths"):
            graded.append((trigger, set(config["paths"])))
        if config.get("paths-ignore"):
            ignored.append(trigger)
    return graded, ignored


def report(workflow, trigger, listed, packages):
    """Print each path this filter is missing. Returns how many."""
    # Grouped by what is missing rather than by what needs it: one line per
    # path to add is what somebody fixing this wants to read.
    needed_by = {}
    for entry in sorted(listed):
        for crate in sorted(
            name for name, (path, _, _) in packages.items() if matches(entry, path)
        ):
            required = {packages[d][0] for d in closure(crate, packages)}
            required |= packages[crate][2]
            for path in required:
                if not covers(listed, path):
                    needed_by.setdefault(path, set()).add(crate)
    for path, crates in sorted(needed_by.items()):
        # Named exactly, not globbed: a submodule is one gitlink entry (see
        # `matches`) and a manifest or lockfile is one file.
        bare = path.startswith("submodules/") or path.endswith((".toml", ".lock"))
        suggestion = path if bare else path + "/**"
        print(
            f"{workflow} ({trigger}): add '{suggestion}' -- needed by "
            f"{', '.join(sorted(crates))}"
        )
    return len(needed_by)


def main():
    packages = graph()
    gaps = 0
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    if not workflows:
        print("no workflows found -- this check is not looking where it thinks")
        return 2
    for workflow in workflows:
        graded, ignored = filters(workflow.read_text())
        for trigger in ignored:
            # Said out loud rather than passed over: a filter nothing grades is
            # a filter nobody is watching, and silence is how the two blind
            # spots above survived.
            print(f"{workflow.name} ({trigger}): paths-ignore, not checked")
        for trigger, listed in graded:
            gaps += report(workflow.name, trigger, listed, packages)
    if gaps:
        print(f"\n{gaps} paths to add. A filter must be closed.")
        return 1
    print(f"every paths filter in {len(workflows)} workflows is closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
