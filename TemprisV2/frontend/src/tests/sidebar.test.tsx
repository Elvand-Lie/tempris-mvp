import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ModuleNotEntitled } from '../components/ModuleNotEntitled';
import { Sidebar } from '../components/Sidebar';

describe('Sidebar and module fallback', () => {
  it('renders Assets and Collectors only with the ASSETS entitlement', () => {
    const { rerender } = render(
      <Sidebar activeTab="assets" onTabChange={vi.fn()} effectiveModules={['ASSETS']} currentRole="analyst" />
    );
    expect(screen.getByRole('button', { name: 'Assets Console' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Collectors Console' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'SCOUT' })).toBeInTheDocument();

    rerender(
      <Sidebar activeTab="assets" onTabChange={vi.fn()} effectiveModules={[]} currentRole="analyst" />
    );
    expect(screen.queryByRole('button', { name: 'Assets Console' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Collectors Console' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'SCOUT' })).not.toBeInTheDocument();
  });

  it('gates Organization by role independently of module entitlement', () => {
    const { rerender } = render(
      <Sidebar activeTab="org" onTabChange={vi.fn()} effectiveModules={[]} currentRole="admin" />
    );
    expect(screen.queryByRole('button', { name: 'Organization' })).not.toBeInTheDocument();
    rerender(
      <Sidebar activeTab="org" onTabChange={vi.fn()} effectiveModules={[]} currentRole="superadmin" />
    );
    expect(screen.getByRole('button', { name: 'Organization' })).toBeInTheDocument();
  });

  it('never renders platform administration in the tenant sidebar', () => {
    render(
      <Sidebar activeTab="org" onTabChange={vi.fn()} effectiveModules={['ASSETS']} currentRole="superadmin" />
    );
    expect(screen.queryByText('Platform Administration')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Platform Console' })).not.toBeInTheDocument();
  });

  it('changes tabs and exposes an accessible collapse control', () => {
    const onTabChange = vi.fn();
    render(
      <Sidebar activeTab="assets" onTabChange={onTabChange} effectiveModules={['ASSETS']} currentRole="analyst" />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Collectors Console' }));
    expect(onTabChange).toHaveBeenCalledWith('collectors');
    const toggle = screen.getByRole('button', { name: 'Collapse navigation' });
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(toggle);
    expect(screen.getByRole('button', { name: 'Expand navigation' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('renders the exact unentitled module guidance', () => {
    render(<ModuleNotEntitled module="ASSETS" />);
    expect(screen.getByText('Your organization does not have access to the ASSETS module. Please contact your platform administrator.')).toBeInTheDocument();
  });
});
