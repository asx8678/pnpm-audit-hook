/**
 * Binary Search Utilities for Sorted Package Lists
 *
 * Provides efficient O(log n) lookups for package names in sorted arrays,
 * used for fast existence checks against the static vulnerability database index.
 */

/**
 * Binary search for a package name in a sorted list.
 */
export function binarySearchPackage(sortedPackages: string[], packageName: string): boolean {
  let left = 0;
  let right = sortedPackages.length - 1;

  while (left <= right) {
    const mid = Math.floor((left + right) / 2);
    const midValue = sortedPackages[mid];
    if (midValue === undefined) {
      return false;
    }
    const comparison = packageName.localeCompare(midValue);

    if (comparison === 0) {
      return true;
    } else if (comparison < 0) {
      right = mid - 1;
    } else {
      left = mid + 1;
    }
  }

  return false;
}
