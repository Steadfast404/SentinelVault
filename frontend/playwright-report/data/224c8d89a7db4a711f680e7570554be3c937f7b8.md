# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: smoke.spec.ts >> api readyz endpoint proxy works
- Location: e2e\smoke.spec.ts:1:189

# Error details

```
Error: expect(received).toBe(expected) // Object.is equality

Expected: 200
Received: 500
```

# Test source

```ts
> 1 | import { test, expect } from '@playwright/test'; test('landing page loads', async ({ page }) => { await page.goto('/'); await expect(page.getByText('Landing Page')).toBeVisible(); }); test('api readyz endpoint proxy works', async ({ request }) => { const response = await request.get('/api/v1/readyz'); expect(response.status()).toBe(200); });
    |                                                                                                                                                                                                                                                                                                                                          ^ Error: expect(received).toBe(expected) // Object.is equality
  2 | 
```