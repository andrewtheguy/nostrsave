# TODO

## Testing

### Test File Index Pagination with Smaller Threshold
Test the O(1) archive pagination logic end-to-end with a smaller `MAX_INDEX_ENTRIES` (e.g., 5 instead of 1000):
- Verify archiving triggers correctly when threshold is reached
- Test page navigation across multiple archives
- Confirm archive immutability (old archives unchanged after new uploads)
- Validate `total_archives` consistency between current index and archives
- Test edge cases: empty index, single archive, many archives
