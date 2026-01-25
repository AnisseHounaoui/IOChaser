
let allIocData = null;

// Search bar (search trigger on every character input)
document.addEventListener("DOMContentLoaded", () => {
  const searchInput = document.getElementById("ioc-search");

  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase();
      if (!allIocData) return;

      const filtered = {
        ips: allIocData.ips.filter(i => i.toLowerCase().includes(query)),
        domains: allIocData.domains.filter(i => i.toLowerCase().includes(query)),
        hashes: allIocData.hashes.filter(i => i.toLowerCase().includes(query)),
        emails: allIocData.emails.filter(i => i.toLowerCase().includes(query)),
      };

      displayIOCs(filtered);
    });
  }
});

// Tabbed Navigations (IOCs and Settings)
document.addEventListener("DOMContentLoaded", () => {
  const tabs = {
    "tab-iocs": document.getElementById("ioc-tab"),
    "tab-settings": document.getElementById("settings-tab")
  };

  document.querySelectorAll("#tab-buttons .tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#tab-buttons .tab").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      tabs[btn.id].classList.add("active");
    });
  });
});

// Private IP logic
function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

// Create VT button (IP/domain/hash)
function createVTScanButton(ioc, type, parentDiv) {
  const btn = document.createElement('button');
  btn.textContent = "🔍";
  btn.title = "Scan via VirusTotal";

  btn.onclick = async () => {
    if (type === "ip" && isPrivateIP(ioc)) {
      const resultSpan = document.createElement('span');
      resultSpan.style.marginLeft = '6px';
      resultSpan.textContent = "Private IP";
      resultSpan.style.color = "LightGray";
      btn.replaceWith(resultSpan);
      return;
    }

    btn.textContent = "⏳";

    // Fetch VT and abuseIPDB
    const [scoreData, abuseData] = await Promise.all([
      getVirusTotalScore(ioc, type),
      type === "ip" ? getAbuseIPDBInfo(ioc) : null
    ]);

    const resultSpan = document.createElement('span');
    resultSpan.style.marginLeft = '6px';

    // Add abuseIPDB country 
    if (abuseData && abuseData.country !== "Unknown") {
      resultSpan.textContent = ` [${abuseData.country}] `;
    }

    // Add VT results
    if (scoreData) {
      const { positives, total, resolvedIp, meaningful_name } = scoreData;

      if (positives > 0) {
        resultSpan.textContent += `${positives}/${total} Malicious`;
        resultSpan.style.color = "red";
      } else {
        resultSpan.textContent += `Clean`;
        resultSpan.style.color = "green";
      }

      if (resolvedIp) {
        resultSpan.textContent += ` • IP: ${resolvedIp}`;
        resultSpan.title = resolvedIp;
      }

      if (meaningful_name) {
        resultSpan.textContent += ` • [${meaningful_name}]`;
        resultSpan.title = meaningful_name;
      }
    } else {
      resultSpan.textContent = `Not found`;
      resultSpan.style.color = "gray";
    }

    if (abuseData && abuseData.reports >= 1 && resultSpan.style.color === "green") {
      resultSpan.style.color = "orange";
    }

    if (abuseData && (abuseData.confidence !== 0 || abuseData.reports !== 0)) {
      resultSpan.textContent += ` • ${abuseData.confidence}% (${abuseData.reports} rep.)`;
      resultSpan.title = resultSpan.textContent;
    }


    btn.replaceWith(resultSpan);
  };

  return btn;
}


// Create HIBP button (email)
function createHIBPScanButton(email) {
  const btn = document.createElement('button');
  btn.textContent = "🕵️";
  btn.title = "Verify via Have I Been Pwned";

  btn.onclick = async () => {
    btn.textContent = "⏳";

    const result = await checkHIBP(email);

    const wrapper = document.createElement('span');
    wrapper.style.display = "inline-flex";
    wrapper.style.alignItems = "center";
    wrapper.style.gap = "6px";
    wrapper.style.marginLeft = "6px";

    const resultSpan = document.createElement('span');

    if (result?.error === "NO_API_KEY") {
      resultSpan.textContent = "API key missing";
      resultSpan.style.color = "gray";
      wrapper.appendChild(resultSpan);
    }

    else if (result?.error === "API_ERROR") {
      resultSpan.textContent = "API error";
      resultSpan.style.color = "gray";
      wrapper.appendChild(resultSpan);
    }
    else if (result.breached) {
      resultSpan.textContent = `PWNED • ${result.count} Breaches`;
      resultSpan.style.color = "red";
      resultSpan.title = result.breaches.join(", ");
      wrapper.appendChild(resultSpan);

      const detailBtn = document.createElement('button');
      detailBtn.textContent = "📄";
      detailBtn.title = "Show details";
      // Modal filling
      detailBtn.onclick = () => {
        const modal = document.createElement('div');
        modal.style = `
          position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
          background: rgba(0,0,0,0.8); color: white; padding: 20px;
          border-radius: 8px; width: 80%; max-width: 500px;
          z-index: 9999; overflow-y: auto; max-height: 70%;
        `;

        const title = document.createElement('h2');
        title.textContent = `Breach Details for: ${email}`;
        modal.appendChild(title);

        const list = document.createElement('ul');
        result.breaches.forEach(b => {
          const li = document.createElement('li');
          li.textContent = b;
          list.appendChild(li);
        });
        modal.appendChild(list);

        const closeBtn = document.createElement('span');
        closeBtn.textContent = "✖";
        closeBtn.style = "position:absolute; top:10px; right:10px; cursor:pointer; font-weight:bold;";
        closeBtn.onclick = () => document.body.removeChild(modal);
        modal.appendChild(closeBtn);

        document.body.appendChild(modal);
      };

      wrapper.appendChild(detailBtn);
    }

    else {
      resultSpan.textContent = "Not pwned";
      resultSpan.style.color = "green";
      wrapper.appendChild(resultSpan);
    }

    btn.replaceWith(wrapper);
  };

  return btn;
}


// Copy button (right one)
function createCopyButton(text) {
  const btn = document.createElement('button');
  btn.textContent = "📋";
  btn.title = "Copy to clipboard";

  btn.onclick = () => {
    navigator.clipboard.writeText(text).then(() => {
      btn.textContent = "✔";
      setTimeout(() => btn.textContent = "📋", 2000);
    });
  };

  return btn;
}

// External TI botton
function createLinkButton(label, url) {
  const btn = document.createElement('button');
  btn.textContent = label;
  btn.onclick = () => chrome.runtime.sendMessage({ action: "openToolTab", url });
  return btn;
}

// HIBP api call
async function checkHIBP(email) {
  const hibpApiKey = await new Promise(resolve =>
    chrome.storage.local.get("hibpApiKey", data => resolve(data.hibpApiKey))
  );

  if (!hibpApiKey) {
    return { error: "NO_API_KEY" };
  }

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      {
        method: "GET",
        headers: {
          "hibp-api-key": hibpApiKey,
          "user-agent": "IOChaser/1.0"
        }
      }
    );

    if (response.status === 404) {
      return { breached: false };
    }

    if (!response.ok) {
      return { error: "API_ERROR" };
    }

    const data = await response.json();
    return {
      breached: true,
      count: data.length,
      breaches: data.map(b => b.Name)
    };

  } catch (e) {
    console.error(e);
    return { error: "API_ERROR" };
  }
}


async function getCountryNameFromCode(code) {
  try {
    const res = await fetch(`https://restcountries.com/v3.1/alpha/${code}`);
    if (!res.ok) throw new Error("Failed to fetch country");
    const data = await res.json();
    return data[0].name.common;
  } catch (e) { console.error(e); return code; }
}

async function getAbuseIPDBInfo(ip) {
  const abuseApiKey = await new Promise(resolve =>
    chrome.storage.local.get("abuseApiKey", data => resolve(data.abuseApiKey))
  );

  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: { Key: abuseApiKey, Accept: "application/json" }
    });
    if (!res.ok) return null;

    const data = await res.json();
    const countryName = await getCountryNameFromCode(data.data.countryCode);

    return { confidence: data.data.abuseConfidenceScore, reports: data.data.totalReports, country: countryName };
  } catch (e) { console.error(e); return null; }
}

async function getVirusTotalScore(ioc, type) {
  const apiKey = await new Promise(resolve => {
    chrome.storage.local.get("vtApiKey", data => resolve(data.vtApiKey));
  });

  let url = "";
  if (type === "ip") {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
  } else if (type === "domain") {
    url = `https://www.virustotal.com/api/v3/domains/${ioc}`;
  } else if (type === "hash") {
    url = `https://www.virustotal.com/api/v3/files/${ioc}`;
  } else {
    return null;
  }

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { "x-apikey": apiKey }
    });

    if (!response.ok) return null;

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    let resolvedIp = null;
    if (type === "domain" && data.data.attributes.last_dns_records) {
      const aRecord = data.data.attributes.last_dns_records.find(r => r.type === "A");
      if (aRecord) resolvedIp = aRecord.value;
    }

    let meaningful_name = null;
    if (type === "hash" && data.data.attributes.meaningful_name) {
      meaningful_name = data.data.attributes.meaningful_name;
    }

    return {
      positives: stats.malicious,
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      resolvedIp,
      meaningful_name
    };
  } catch (error) {
    console.error("Error during API call:", error);
    return null;
  }
}



// IOCs Display on popup
function displayIOCs(iocs) {
  const container = document.getElementById('results');
  container.innerHTML = "";

  const groups = [
    { title: "IP Addresses", items: iocs.ips, type: "ip" },
    { title: "Domains", items: iocs.domains, type: "domain" },
    { title: "Hashes", items: iocs.hashes, type: "hash" },
    { title: "Emails", items: iocs.emails, type: "email" }
  ];

  groups.forEach(group => {
    if (group.items.length === 0) return;

    const section = document.createElement('div');
    const title = document.createElement('h3');
    title.textContent = group.title;
    section.appendChild(title);

    group.items.forEach(ioc => {
      const div = document.createElement('div');
      div.className = "ioc-item";

      const topLine = document.createElement('div');
      topLine.className = "ioc-header";

      const text = document.createElement('span');
      text.textContent = ioc;
      topLine.appendChild(text);

      if (group.type === "email") topLine.appendChild(createHIBPScanButton(ioc));
      else topLine.appendChild(createVTScanButton(ioc, group.type));

      topLine.appendChild(createCopyButton(ioc));
      div.appendChild(topLine);

      const buttonGroup = document.createElement('div');
      buttonGroup.className = "ioc-buttons";

      chrome.storage.local.get("toolSettings", ({ toolSettings }) => {
        const selectedTools = toolSettings?.[group.type] || [];

        const links = {
          ip: {
            virustotal: `https://www.virustotal.com/gui/ip-address/${ioc}`,
            abuseipdb: `https://www.abuseipdb.com/check/${ioc}`,
            ipqs: `https://www.ipqualityscore.com/vpn-ip-address-check/lookup/${ioc}`,
            shodan: `https://www.shodan.io/host/${ioc}`,
            censys: `https://search.censys.io/hosts/${ioc}`,
            greynoise: `https://viz.greynoise.io/ip/${ioc}`,
            talos: `https://talosintelligence.com/reputation_center/lookup?search=${ioc}`
          },
          domain: {
            virustotal: `https://www.virustotal.com/gui/domain/${ioc}`,
            urlscan: `https://urlscan.io/domain/${ioc}`,
            alienvault: `https://otx.alienvault.com/indicator/hostname/${ioc}`
          },
          hash: {
            virustotal: `https://www.virustotal.com/gui/file/${ioc}`,
            hybrid: `https://www.hybrid-analysis.com/search?query=${ioc}`
          },
          email: {
            google: `https://www.google.com/search?q="${ioc}"`,
            hibp: `https://haveibeenpwned.com/account/${ioc}`
          }
        };

        selectedTools.forEach(tool => {
          if (links[group.type][tool]) buttonGroup.appendChild(createLinkButton(tool, links[group.type][tool]));
        });

        div.appendChild(buttonGroup);
      });

      section.appendChild(div);
    });

    container.appendChild(section);
  });
}

// Initialisations
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.tabs.sendMessage(tab.id, { action: "getIOCs" }, (response) => {
    if (chrome.runtime.lastError) {
      console.error("Error:", chrome.runtime.lastError.message);
      document.getElementById('results').textContent = "Unable to scan page.";
      return;
    }
    allIocData = response;
    displayIOCs(response);
  });
});

// API keys storage management
document.getElementById("save-api-keys").addEventListener("click", () => {
  const vtKey = document.getElementById("vt-api-key").value.trim();
  const abuseKey = document.getElementById("abuse-api-key").value.trim();
  const hibpKey = document.getElementById("hibp-api-key").value.trim();

  chrome.storage.local.set({ vtApiKey: vtKey, abuseApiKey: abuseKey, hibpApiKey: hibpKey }, () => {
    alert("API keys saved!");
    location.reload();
  });
});

window.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["vtApiKey","abuseApiKey","hibpApiKey"], data => {
    if(data.vtApiKey) document.getElementById("vt-api-key").value = data.vtApiKey;
    if(data.abuseApiKey) document.getElementById("abuse-api-key").value = data.abuseApiKey;
    if(data.hibpApiKey) document.getElementById("hibp-api-key").value = data.hibpApiKey;
  });
});

// Tools config storage
document.getElementById("save-tool-settings").addEventListener("click", () => {
  const toolCheckboxes = document.querySelectorAll('#tool-settings input[type="checkbox"]');
  const toolSettings = {};

  toolCheckboxes.forEach(cb => {
    const type = cb.dataset.type;
    if(!toolSettings[type]) toolSettings[type] = [];
    if(cb.checked) toolSettings[type].push(cb.value);
  });

  chrome.storage.local.set({ toolSettings }, () => {
    alert("Tool preferences saved!");
    location.reload();
  });
});

window.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["toolSettings"], ({toolSettings}) => {
    if(!toolSettings) return;
    document.querySelectorAll('#tool-settings input[type="checkbox"]').forEach(cb => {
      const type = cb.dataset.type;
      if(toolSettings[type]?.includes(cb.value)) cb.checked = true;
    });
  });
});
