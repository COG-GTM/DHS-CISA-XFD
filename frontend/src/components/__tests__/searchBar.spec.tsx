import React from 'react';
import { render } from 'test-utils';
import { SearchBar } from '../FilterDrawer/SearchBar';
import { vi } from 'vitest';

it('matches snapshot', () => {
  const { asFragment } = render(
    <SearchBar
      onChange={vi.fn()}
      autocompletedResults={[]}
      onSelectResult={vi.fn()}
    />
  );
  expect(asFragment()).toMatchSnapshot();
});
