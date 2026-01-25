function extractIOCsFromText(text) {
  const iocs = {
    ips: new Set(),
    domains: new Set(),
    hashes: new Set(),
    emails: new Set()
  };

  // Regex IOCs logic
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g; 
  const domainRegex = /(?<!@)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,})/g; 
  const hashRegex = /\b[a-fA-F0-9]{32,64}\b/g; // md5, sha1, sha256
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;  

  // Supported domain tlds (as of now)
  const validTLDs = new Set([
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
    'co', 'uk', 'de', 'jp', 'fr', 'au', 'us', 'ru', 'ch', 'it',
    'nl', 'se', 'info', 'biz', 'online', 'xyz', 'site', 'io',
    'app', 'tech', 'dev', 'me', 'ai', 'in', 'ca', 'br'
  ]);
  // Find and store the IOCs
  let match;
  while ((match = ipRegex.exec(text))) iocs.ips.add(match[0]);  
  while ((match = hashRegex.exec(text))) iocs.hashes.add(match[0]);
  while ((match = emailRegex.exec(text))) iocs.emails.add(match[0]);

  const rawEmails = [];
while ((match = emailRegex.exec(text))) {
  const email = match[0];
  iocs.emails.add(email);

  // to extract domains from emails (in phishing cases)
  const domainFromEmail = email.split('@')[1];
  const tld = domainFromEmail.split('.').pop().toLowerCase();
  if (validTLDs.has(tld)) {
    iocs.domains.add(domainFromEmail.toLowerCase());
  }
}

// domains (not in emails)
const rawDomains = [];
while ((match = domainRegex.exec(text))) {
  const domain = match[0].toLowerCase();

  if (![...iocs.emails].some(email => email.includes(domain))) {
    const tld = domain.split('.').pop();
    if (validTLDs.has(tld)) {
      iocs.domains.add(domain);
    }
  }
}


  console.log("Extracted IOCs: ", iocs);

  return {
    ips: [...iocs.ips], 
    domains: [...iocs.domains],
    hashes: [...iocs.hashes],
    emails: [...iocs.emails]
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getIOCs") {
    const iocs = extractIOCsFromText(document.body.innerText);
    sendResponse(iocs);
  }
});
