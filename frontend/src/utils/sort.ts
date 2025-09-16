/*
    Name: sort.ts
    Author: Jesse Salinas
    Date: 2024-09-16
    Description: Utility functions for natural sorting
*/

// Natural sorting compares numbers within strings (e.g., "domain2.com" vs "domain10.com")
export function naturalCompare(a: string, b: string): number {
  const tokenize = (str: string): (string | number)[] => {
    return (str.match(/(\d+|\D+)/g) || []).map((s) => {
      const n = Number(s);
      return isNaN(n) ? s : n;
    });
  };

  const ax = tokenize(a);
  const bx = tokenize(b);

  for (let i = 0; i < Math.max(ax.length, bx.length); i++) {
    if (ax[i] === undefined) return -1;
    if (bx[i] === undefined) return 1;
    if (typeof ax[i] === 'number' && typeof bx[i] === 'number') {
      if (ax[i] !== bx[i]) return (ax[i] as number) - (bx[i] as number);
    } else if (ax[i] !== bx[i]) {
      return String(ax[i]).localeCompare(String(bx[i]));
    }
  }
  return 0;
}

// Sorting should treat each octet as a number (e.g., "10.1.1.1" vs "2.1.1.1"), not as a string.
export function ipCompare(a: string, b: string): number {
  const toNum = (ip: string) => ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
  return toNum(a) - toNum(b);
}
