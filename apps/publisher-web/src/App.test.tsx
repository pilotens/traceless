import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import App from './App';

const pages: Record<string, unknown> = {
  '/publisher-admin/admin/v2/accounts?limit=200&offset=0': { items: [{ id:'a1',account_key:'acme',name:'Acme',enabled:true,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:00Z' }], total:1,limit:200,offset:0 },
  '/publisher-admin/admin/v1/installations?limit=200&offset=0': { items: [], total:0,limit:200,offset:0 },
  '/publisher-review/admin/v1/records?limit=200&offset=0': { items: [], total:0,limit:200,offset:0 },
  '/publisher-admin/admin/v1/imports?limit=200&offset=0': { items: [], total:0,limit:200,offset:0 },
  '/publisher-feed/.well-known/traceless-intelligence-signing-keys': { schema_version:'1.0',generated_at:'2026-01-01T00:00:00Z',active_key_id:'key-1',keys:[] },
};

describe('Publisher workspace', () => {
  test('keeps a manually entered token in memory and loads publisher data', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(pages[String(input)]), { status:200, headers:{'Content-Type':'application/json'} })) as typeof fetch;
    render(<App oidcConfiguration={{mode:'disabled'}} fetchImpl={fetchImpl} />);
    await userEvent.type(screen.getByLabelText('Admin-token'), 'publisher-admin-token-0000000000000000');
    await userEvent.type(screen.getByLabelText('Reviewer-token'), 'publisher-review-token-000000000000000');
    await userEvent.click(screen.getByRole('button',{name:'Anslut'}));
    await userEvent.click(await screen.findByRole('button', { name: 'Kundkonton' }));
    await waitFor(() => expect(screen.getByText('Acme')).toBeInTheDocument());
    expect(fetchImpl).toHaveBeenCalled();
  });

  test('switches the publisher shell language', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(pages[String(input)]), { status:200, headers:{'Content-Type':'application/json'} })) as typeof fetch;
    render(<App oidcConfiguration={{mode:'disabled'}} fetchImpl={fetchImpl} />);
    await userEvent.type(screen.getByLabelText('Admin-token'), 'publisher-admin-token-0000000000000000');
    await userEvent.type(screen.getByLabelText('Reviewer-token'), 'publisher-review-token-000000000000000');
    await userEvent.click(screen.getByRole('button',{name:'Anslut'}));
    await userEvent.selectOptions(await screen.findByLabelText('Språk'), 'en');
    expect(screen.getByText('Intelligence Publisher')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Customer accounts'})).toBeInTheDocument();
  });
});
