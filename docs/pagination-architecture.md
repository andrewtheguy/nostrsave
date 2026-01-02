# File Index Pagination Architecture

## Overview

The file index uses **immutable archives** for O(1) upload performance. When the current
index fills up, its entries are frozen to a new archive and a fresh index is created.

## Page Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Index Relays                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐                                               │
│  │  Current Index   │  d-tag: "nostrsave-index"                     │
│  │    (Page 1)      │                                               │
│  ├──────────────────┤                                               │
│  │ total_archives: 3│                                               │
│  │ entries[0..500]  │  ← newest files (1-1000 entries)              │
│  └──────────────────┘                                               │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   Archive 3      │  │   Archive 2      │  │   Archive 1      │  │
│  │    (Page 2)      │  │    (Page 3)      │  │    (Page 4)      │  │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────────┤  │
│  │ d: nostrsave-    │  │ d: nostrsave-    │  │ d: nostrsave-    │  │
│  │    index-        │  │    index-        │  │    index-        │  │
│  │    archive-3     │  │    archive-2     │  │    archive-1     │  │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────────┤  │
│  │ entries[0..1000] │  │ entries[0..1000] │  │ entries[0..1000] │  │
│  │ (most recent     │  │                  │  │ (oldest          │  │
│  │  archive)        │  │                  │  │  archive)        │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│      IMMUTABLE           IMMUTABLE             IMMUTABLE           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Page to Archive Mapping

```
Page 1  →  Current Index (d-tag: nostrsave-index)
Page 2  →  Archive N     (d-tag: nostrsave-index-archive-N)     ← most recent archive
Page 3  →  Archive N-1   (d-tag: nostrsave-index-archive-(N-1))
...
Page N+1 → Archive 1     (d-tag: nostrsave-index-archive-1)     ← oldest archive
```

Formula: `archive_number = total_archives + 2 - page`

## Normal Upload (No Archiving)

When current index has room (< 1000 entries):

```
                    ┌─────────────┐
                    │  New File   │
                    └──────┬──────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 1. Fetch current index │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  2. Add entry to index │
              │     (500 → 501)        │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 3. Publish current idx │
              └────────────────────────┘

              Fetches: 1
              Publishes: 1
              Complexity: O(1)
```

## Upload with Archiving (O(1))

When current index is full (1000+ entries):

```
                    ┌─────────────┐
                    │  New File   │
                    └──────┬──────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 1. Fetch current index │
              │    (1000 entries)      │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 2. Create Archive N+1  │
              │    with 1000 old files │
              │    (IMMUTABLE)         │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 3. Create fresh index  │
              │    with 1 new file     │
              │    total_archives: N+1 │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ 4. Publish archive     │
              │ 5. Publish new index   │
              └────────────────────────┘

              Fetches: 1
              Publishes: 2
              Complexity: O(1)  ← ALWAYS, regardless of archive count!
```

## Visual: Before and After Archiving

```
BEFORE (1000 files in current index):

  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  Current Index  │     │   Archive 2     │     │   Archive 1     │
  │   (1000 files)  │     │  (1000 files)   │     │  (1000 files)   │
  │ total_archives:2│     │                 │     │                 │
  └─────────────────┘     └─────────────────┘     └─────────────────┘
        Page 1                 Page 2                  Page 3


AFTER adding 1 new file (triggers archiving):

  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  Current Index  │     │   Archive 3     │     │   Archive 2     │     │   Archive 1     │
  │    (1 file)     │     │  (1000 files)   │     │  (1000 files)   │     │  (1000 files)   │
  │ total_archives:3│     │   (NEW!)        │     │                 │     │                 │
  └─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
        Page 1                 Page 2                  Page 3                  Page 4
           │                      ▲
           │                      │
           └──────────────────────┘
              Old 1000 files moved here
              (frozen, never modified)
```

## Complexity Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                     Upload Scenarios                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Scenario                      Fetches    Publishes   O(?)      │
│  ─────────────────────────────────────────────────────────────  │
│  Current index has room        1          1           O(1)      │
│  Current index full            1          2           O(1)      │
│  50 archives, index full       1          2           O(1)      │
│  1000 archives, index full     1          2           O(1)      │
│                                                                 │
│  Key: Archives are NEVER re-fetched or re-published!            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      List Scenarios                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Scenario                      Fetches    Complexity            │
│  ─────────────────────────────────────────────────────────────  │
│  nostrsave list (page 1)       1          O(1)                  │
│  nostrsave list --page 2       2*         O(1)                  │
│  nostrsave list --page 50      2*         O(1)                  │
│                                                                 │
│  * First fetch current index to get total_archives,            │
│    then fetch the specific archive                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Why This Design?

```
┌─────────────────────────────────────────────────────────────────┐
│  Design: Immutable Archives with Incrementing Numbers           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Pros:                                                          │
│  ✓ Upload ALWAYS O(1) - never touch old archives                │
│  ✓ "Recent files" (page 1) = 1 fetch                            │
│  ✓ Deterministic identifiers (no event ID linking)              │
│  ✓ Each archive independently fetchable                         │
│  ✓ Archives are immutable (simple, reliable)                    │
│  ✓ Scales to unlimited files without performance degradation    │
│                                                                 │
│  Cons:                                                          │
│  ✗ Page 2+ requires 2 fetches (first get total_archives)        │
│  ✗ Current index may have few entries after archiving           │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Previous Design (Cascading) - REJECTED                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Problem: When all N pages were full, adding one file           │
│           required N fetches and N+1 publishes (O(N))           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
                              UPLOAD
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Chunk file & encrypt │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
            ┌─────────────┐         ┌─────────────┐
            │ Data Relays │         │Index Relays │
            │             │         │             │
            │ - Chunks    │         │ - Manifest  │
            │   (kind     │         │   (kind     │
            │    30078)   │         │    30079)   │
            │             │         │             │
            │             │         │ - File Index│
            │             │         │   (kind     │
            │             │         │    30080)   │
            │             │         │             │
            │             │         │ - Archives  │
            │             │         │   (kind     │
            │             │         │    30080)   │
            └─────────────┘         └─────────────┘


                              LIST
                                │
                                ▼
                    ┌───────────────────────┐
                    │  Fetch current index  │◄─── Index Relays
                    │  (get total_archives) │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │  page == 1?           │
                    ├───────────┬───────────┤
                    │  Yes      │    No     │
                    ▼           │           ▼
               ┌────────┐       │    ┌────────────────┐
               │  Done  │       │    │ Fetch archive  │
               └────────┘       │    │ by number      │
                                │    └────────────────┘
```

## Identifiers Reference

| Type | d-tag | Description |
|------|-------|-------------|
| Current Index | `nostrsave-index` | Always page 1, 1-1000 entries |
| Archive 1 | `nostrsave-index-archive-1` | Oldest archive |
| Archive 2 | `nostrsave-index-archive-2` | Second oldest |
| Archive N | `nostrsave-index-archive-N` | Most recent archive (page 2) |
