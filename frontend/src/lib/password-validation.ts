/**
 * Password validation utilities including HIBP (Have I Been Pwned) API integration
 */

/**
 * Returns SHA-1 hex string of input using Web Crypto API
 */
async function sha1Hex(input: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Check password against HIBP k-Anonymity API
 * @param password - The password to check
 * @returns The number of times the password has appeared in data breaches (0 if not found)
 */
export async function isPwnedPassword(password: string): Promise<number> {
  if (!password) return 0;
  
  try {
    const hash = await sha1Hex(password); // uppercase hex
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      method: 'GET',
      headers: { 'Add-Padding': 'true' } // optional, privacy padding
    });
    
    if (!res.ok) throw new Error('HIBP request failed');
    
    const text = await res.text();
    // response lines: "HASH_SUFFIX:COUNT"
    const lines = text.split('\n');
    
    for (const line of lines) {
      const [returnedSuffix, count] = line.trim().split(':');
      if (!returnedSuffix) continue;
      if (returnedSuffix.toUpperCase() === suffix) {
        return parseInt(count || '0', 10); // number of times seen
      }
    }
    
    return 0; // not found
  } catch (error) {
    console.error('Error checking password against HIBP:', error);
    // If the HIBP check fails, we don't want to block signup entirely
    // Return 0 and let the user proceed
    return 0;
  }
}

/**
 * Validates password strength with local checks
 * @param password - The password to validate
 * @throws Error with user-friendly message if password doesn't meet requirements
 */
export function validatePasswordStrength(password: string): void {
  if (password.length < 12) {
    throw new Error('Password too short — use at least 12 characters.');
  }
  
  // Check for at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    throw new Error('Password must contain at least one uppercase letter.');
  }
  
  // Check for at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    throw new Error('Password must contain at least one lowercase letter.');
  }
  
  // Check for at least one number
  if (!/[0-9]/.test(password)) {
    throw new Error('Password must contain at least one number.');
  }
  
  // Check for at least one special character
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    throw new Error('Password must contain at least one special character.');
  }
}

/**
 * Complete password validation including local strength checks and HIBP check
 * @param password - The password to validate
 * @returns Promise that resolves if password is valid, rejects with Error if not
 */
export async function validatePassword(password: string): Promise<void> {
  // 1) Local strength checks
  validatePasswordStrength(password);
  
  // 2) HIBP check
  const pwnCount = await isPwnedPassword(password);
  if (pwnCount > 0) {
    // Block and show friendly message
    throw new Error(
      `This password has appeared in data breaches ${pwnCount.toLocaleString()} time${pwnCount !== 1 ? 's' : ''}. Please choose a different password.`
    );
  }
}
