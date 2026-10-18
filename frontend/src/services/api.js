const API_BASE = "/api";

const tokenCache = new Map();

export async function getAuthToken(tenantId = "tenant-corp-alpha", role = "analyst") {
  const cacheKey = `${tenantId}:${role}`;
  if (tokenCache.has(cacheKey)) {
    return tokenCache.get(cacheKey);
  }

  const isBeta = tenantId && tenantId.includes("beta");
  let creds;
  if (isBeta) {
    creds = { username: "lead-dave-beta", passphrase: "demo-dave-2026" };
  } else if (role === "lead" || role === "admin") {
    creds = { username: "lead-carol-01", passphrase: "demo-carol-2026" };
  } else {
    creds = { username: "analyst-alice-01", passphrase: "demo-alice-2026" };
  }

  try {
    const res = await fetch(`${API_BASE}/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(creds),
    });
    if (!res.ok) {
      throw new Error(`Authentication failed (${res.status}): ${res.statusText}`);
    }
    const data = await res.json();
    tokenCache.set(cacheKey, data.access_token);
    return data.access_token;
  } catch (err) {
    console.error(`Failed to acquire token for ${creds.username} (${tenantId}):`, err);
    throw err;
  }
}

async function getAuthHeaders(tenantId, role = "analyst") {
  const token = await getAuthToken(tenantId, role);
  const headers = {
    "Content-Type": "application/json",
    "X-Tenant-ID": tenantId,
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export async function runInvestigation(params, tenantId = "tenant-corp-alpha") {
  const headers = await getAuthHeaders(tenantId);
  const res = await fetch(`${API_BASE}/investigate`, {
    method: "POST",
    headers,
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Investigation failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function runAgentInvestigation(params, tenantId = "tenant-corp-alpha") {
  const headers = await getAuthHeaders(tenantId);
  const res = await fetch(`${API_BASE}/agent/investigate`, {
    method: "POST",
    headers,
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Agent investigation failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function submitGateADisposition(payload, tenantId = "tenant-corp-alpha") {
  const headers = await getAuthHeaders(tenantId);
  const res = await fetch(`${API_BASE}/reviews/gate-a/disposition`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Gate A submission failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function authorizeGateBRemediation(payload, tenantId = "tenant-corp-alpha") {
  const headers = await getAuthHeaders(tenantId, "lead");
  const res = await fetch(`${API_BASE}/reviews/gate-b/authorize`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Gate B authorization failed: ${res.statusText}`);
  }
  return await res.json();
}

export async function fetchDecisionHistory(findingId, tenantId = "tenant-corp-alpha", limit = 20) {
  const headers = await getAuthHeaders(tenantId);
  const res = await fetch(`${API_BASE}/investigate/${encodeURIComponent(findingId)}/history?limit=${limit}`, {
    headers,
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Failed to fetch history: ${res.statusText}`);
  }
  return await res.json();
}