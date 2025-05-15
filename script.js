document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Security Scanner Tab
    const scanBtn = document.getElementById('scan-btn');
    const clearBtn = document.getElementById('clear-btn');
    const targetUrl = document.getElementById('target-url');
    const outputBox = document.getElementById('output-box');
    const statusIndicator = document.getElementById('status-indicator');
    
    scanBtn.addEventListener('click', startScan);
    clearBtn.addEventListener('click', clearOutput);
    
    function logMessage(message, type = 'info') {
        const now = new Date();
        const timeString = now.toTimeString().split(' ')[0];
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `[<span class="log-time">${timeString}</span>] <span class="log-${type}">${message}</span>`;
        outputBox.appendChild(logEntry);
        outputBox.scrollTop = outputBox.scrollHeight;
        return logEntry;
    }
    
    function logVulnerability(title, description, severity = 'high', confidence = 'high') {
        const vulnEntry = document.createElement('div');
        vulnEntry.className = 'vulnerability';
        vulnEntry.innerHTML = `
            <div class="vulnerability-title">
                <span class="severity severity-${severity}">${severity.toUpperCase()}</span>
                ${title}
                <span class="confidence confidence-${confidence}">(${confidence} confidence)</span>
            </div>
            <div class="vulnerability-desc">${description}</div>
        `;
        outputBox.appendChild(vulnEntry);
        outputBox.scrollTop = outputBox.scrollHeight;
        return vulnEntry;
    }
    
    async function startScan() {
        const url = targetUrl.value.trim();
        if (!url) {
            logMessage('Please enter a valid URL', 'danger');
            return;
        }
        
        try {
            new URL(url);
        } catch (e) {
            logMessage('Please enter a valid URL (include http:// or https://)', 'danger');
            return;
        }
        
        const options = {
            headersScan: document.getElementById('headers-scan').checked,
            clickjacking: document.getElementById('clickjacking').checked,
            cors: document.getElementById('cors').checked,
            csp: document.getElementById('csp').checked
        };
        
        if (!Object.values(options).some(opt => opt)) {
            logMessage('Please select at least one scan option', 'danger');
            return;
        }
        
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        statusIndicator.classList.add('status-active');
        logMessage(`Starting security scan for ${url}`, 'info');
        
        try {
            // Fetch the target URL to get headers and content
            const response = await fetch(url, {
                method: 'GET',
                mode: 'no-cors',
                credentials: 'omit',
                redirect: 'follow'
            });
            
            // Get headers as an object
            const headers = {};
            if (response.headers) {
                for (const [key, value] of response.headers.entries()) {
                    headers[key] = value;
                }
            }
            

            const html = await response.text();
            
            // Execute selected scans
            if (options.headersScan) await checkSecurityHeaders(headers);
            if (options.clickjacking) await testClickjacking(headers, html);
            if (options.cors) await testCORS(url);
            if (options.csp) await testCSP(headers, html);
            
            scanComplete();
        } catch (error) {
            logMessage(`Scan failed: ${error.message}`, 'danger');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search"></i> Start Scan';
            statusIndicator.classList.remove('status-active');
            statusIndicator.classList.add('status-danger');
        }
    }
    
    async function checkSecurityHeaders(headers) {
        logMessage('Checking security headers...', 'info');
        
        const securityHeaders = {
            'Strict-Transport-Security': {
                description: 'Ensures all communication is over HTTPS',
                severity: 'high'
            },
            'Content-Security-Policy': {
                description: 'Prevents XSS and other code injection attacks',
                severity: 'high'
            },
            'X-Frame-Options': {
                description: 'Protects against clickjacking attacks',
                severity: 'medium'
            },
            'X-Content-Type-Options': {
                description: 'Prevents MIME type sniffing',
                severity: 'medium'
            },
            'X-XSS-Protection': {
                description: 'Enables XSS filtering in older browsers',
                severity: 'low'
            },
            'Referrer-Policy': {
                description: 'Controls how much referrer information is included',
                severity: 'low'
            },
            'Permissions-Policy': {
                description: 'Controls which browser features can be used',
                severity: 'medium'
            }
        };
        

        for (const [header, info] of Object.entries(securityHeaders)) {
            if (headers[header]) {
                logMessage(`${header}: ${headers[header]}`, 'success');
            } else {
                logVulnerability(
                    `Missing ${header} header`,
                    `${info.description}. This header is recommended for security best practices.`,
                    info.severity,
                    'high'
                );
            }
        }
    }
    
    async function testClickjacking(headers, html) {
        logMessage('Testing for Clickjacking vulnerability...', 'info');
        
       
        if (headers['x-frame-options']) {
            const xfo = headers['x-frame-options'].toLowerCase();
            if (xfo === 'deny' || xfo === 'sameorigin') {
                logMessage('X-Frame-Options header is properly set', 'success');
            } else {
                logVulnerability(
                    'Insecure X-Frame-Options value',
                    `X-Frame-Options is set to "${xfo}" which may not provide complete protection against clickjacking.`,
                    'medium',
                    'high'
                );
            }
        } else {

            if (headers['content-security-policy']) {
                const csp = headers['content-security-policy'].toLowerCase();
                if (csp.includes('frame-ancestors')) {
                    if (csp.includes("'none'") || csp.includes('self')) {
                        logMessage('CSP frame-ancestors directive provides clickjacking protection', 'success');
                    } else {
                        logVulnerability(
                            'Insecure CSP frame-ancestors directive',
                            'Content-Security-Policy frame-ancestors directive allows framing from some sources.',
                            'medium',
                            'high'
                        );
                    }
                } else {
                    logVulnerability(
                        'Missing clickjacking protections',
                        'Neither X-Frame-Options nor CSP frame-ancestors directive are present. The site may be vulnerable to clickjacking.',
                        'medium',
                        'high'
                    );
                }
            } else {
                logVulnerability(
                    'Missing clickjacking protections',
                    'Neither X-Frame-Options header nor Content-Security-Policy with frame-ancestors directive are present. The site is likely vulnerable to clickjacking.',
                    'medium',
                    'high'
                );
            }
        }
        
        
        const hasFrameBusting = html.includes('top.location != self.location') || 
                               html.includes('top !== self') || 
                               html.includes('frame-busting') || 
                               html.includes('framebusting');
        
        if (hasFrameBusting) {
            logMessage('JavaScript framebusting code detected (but may be bypassable)', 'warning');
        }
    }
    
    async function testCORS(targetUrl) {
        logMessage('Testing for CORS misconfigurations...', 'info');
        
        try {
         
            const response = await fetch(targetUrl, {
                method: 'GET',
                headers: {
                    'Origin': 'https://malicious-site.com'
                },
                mode: 'no-cors',
                credentials: 'omit'
            });
            
            const acao = response.headers.get('access-control-allow-origin');
            const acac = response.headers.get('access-control-allow-credentials');
            
            if (acao === '*') {
                if (acac === 'true') {
                    logVulnerability(
                        'Dangerous CORS configuration',
                        'Access-Control-Allow-Origin is set to "*" and Access-Control-Allow-Credentials is true. This allows any website to make authenticated requests to your application.',
                        'high',
                        'high'
                    );
                } else {
                    logVulnerability(
                        'Permissive CORS configuration',
                        'Access-Control-Allow-Origin is set to "*" which allows any website to make requests to your application.',
                        'medium',
                        'high'
                    );
                }
            } else if (acao) {
                logMessage(`CORS is configured to allow origin: ${acao}`, 'info');
            } else {
                logMessage('No CORS headers detected (default same-origin policy enforced)', 'info');
            }
        } catch (error) {
            logMessage(`CORS test failed: ${error.message}`, 'warning');
        }
    }
    
    async function testCSP(headers, html) {
        logMessage('Analyzing Content Security Policy...', 'info');
        
        if (!headers['content-security-policy']) {
            logVulnerability(
                'Missing Content-Security-Policy header',
                'The Content-Security-Policy header is missing. This makes the site vulnerable to XSS attacks and other code injection vulnerabilities.',
                'high',
                'high'
            );
            return;
        }
        
        const csp = headers['content-security-policy'];
        logMessage(`Content-Security-Policy: ${csp}`, 'info');
        
        // Check for common CSP weaknesses
        const issues = [];
        
        if (csp.includes('unsafe-inline')) {
            issues.push('unsafe-inline is enabled (allows inline scripts/styles)');
        }
        
        if (csp.includes('unsafe-eval')) {
            issues.push('unsafe-eval is enabled (allows eval() and similar functions)');
        }
        
        if (csp.includes('*')) {
            issues.push('wildcard (*) source is used (allows loading from any domain)');
        }
        
        if (csp.includes('data:')) {
            issues.push('data: URI is enabled (can be used for XSS)');
        }
        
        if (csp.includes('https:')) {
            issues.push('https: scheme source is used (allows loading from any HTTPS domain)');
        }
        
        if (issues.length > 0) {
            logVulnerability(
                'Content Security Policy issues found',
                `The CSP has the following potential issues: ${issues.join(', ')}. ` +
                'These could make the site vulnerable to XSS attacks or other code injection vulnerabilities.',
                'high',
                'medium'
            );
            
            logMessage('Mitigation: Avoid using unsafe-inline, unsafe-eval, and wildcards in CSP directives. Implement nonces or hashes for inline scripts/styles.', 'warning');
        } else {
            logMessage('Content Security Policy is properly configured with no obvious weaknesses', 'success');
        }
    }
    
    function scanComplete() {
        logMessage('Scan completed', 'success');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-search"></i> Start Scan';
        
        const vulnerabilitiesFound = outputBox.querySelectorAll('.vulnerability').length > 0;
        
        if (vulnerabilitiesFound) {
            statusIndicator.classList.remove('status-active');
            statusIndicator.classList.add('status-danger');
            logMessage('Vulnerabilities were detected during the scan', 'danger');
        } else {
            statusIndicator.classList.remove('status-active');
            statusIndicator.classList.add('status-success');
            logMessage('No critical vulnerabilities were detected', 'success');
        }
    }
    
    function clearOutput() {
        outputBox.innerHTML = '[<span class="log-time">00:00:00</span>] <span class="log-info">Output cleared</span>';
        statusIndicator.className = 'status-indicator';
    }
    
    const encoderInput = document.getElementById('encoder-input');
    const encoderOutput = document.getElementById('encoder-output');
    const copyResultBtn = document.getElementById('copy-result');
    
    document.getElementById('base64-encode').addEventListener('click', () => {
        encoderOutput.value = btoa(encoderInput.value);
    });
    
    document.getElementById('url-encode').addEventListener('click', () => {
        encoderOutput.value = encodeURIComponent(encoderInput.value);
    });
    
    document.getElementById('html-encode').addEventListener('click', () => {
        encoderOutput.value = encoderInput.value.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag]));
    });
    
    document.getElementById('js-encode').addEventListener('click', () => {
        encoderOutput.value = encoderInput.value.replace(/[\\'"\n\r\t]/g, 
            char => ({
                '\\': '\\\\',
                "'": "\\'",
                '"': '\\"',
                '\n': '\\n',
                '\r': '\\r',
                '\t': '\\t'
            }[char]));
    });
    
    document.getElementById('unicode-encode').addEventListener('click', () => {
        encoderOutput.value = Array.from(encoderInput.value).map(c => 
            '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
    });
    
    document.getElementById('hex-encode').addEventListener('click', () => {
        encoderOutput.value = Array.from(encoderInput.value).map(c => 
            '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    });
    
    document.getElementById('base64-decode').addEventListener('click', () => {
        try {
            encoderOutput.value = atob(encoderInput.value);
        } catch (e) {
            encoderOutput.value = 'Error: Invalid Base64 input';
        }
    });
    
    document.getElementById('url-decode').addEventListener('click', () => {
        try {
            encoderOutput.value = decodeURIComponent(encoderInput.value);
        } catch (e) {
            encoderOutput.value = 'Error: Invalid URL-encoded input';
        }
    });
    
    document.getElementById('html-decode').addEventListener('click', () => {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = encoderInput.value;
        encoderOutput.value = textarea.value;
    });
    
    document.getElementById('js-decode').addEventListener('click', () => {
        try {
            encoderOutput.value = encoderInput.value.replace(/\\(.)/g, (match, char) => {
                switch (char) {
                    case 'n': return '\n';
                    case 'r': return '\r';
                    case 't': return '\t';
                    case '\\': return '\\';
                    case '\'': return '\'';
                    case '"': return '"';
                    case 'x': 
                        const hex = match.substr(2, 2);
                        return String.fromCharCode(parseInt(hex, 16));
                    case 'u':
                        const unicode = match.substr(2, 4);
                        return String.fromCharCode(parseInt(unicode, 16));
                    default: return char;
                }
            });
        } catch (e) {
            encoderOutput.value = 'Error: Invalid JavaScript escape sequence';
        }
    });
    
    document.getElementById('unicode-decode').addEventListener('click', () => {
        try {
            encoderOutput.value = encoderInput.value.replace(/\\u([0-9a-fA-F]{4})/g, (match, hex) => {
                return String.fromCharCode(parseInt(hex, 16));
            });
        } catch (e) {
            encoderOutput.value = 'Error: Invalid Unicode escape sequence';
        }
    });
    
    document.getElementById('hex-decode').addEventListener('click', () => {
        try {
            encoderOutput.value = encoderInput.value.replace(/\\x([0-9a-fA-F]{2})/g, (match, hex) => {
                return String.fromCharCode(parseInt(hex, 16));
            });
        } catch (e) {
            encoderOutput.value = 'Error: Invalid hex escape sequence';
        }
    });
    
    copyResultBtn.addEventListener('click', () => {
        if (!encoderOutput.value) {
            alert('No result to copy');
            return;
        }
        
        encoderOutput.select();
        document.execCommand('copy');
        
        const originalText = copyResultBtn.innerHTML;
        copyResultBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
        setTimeout(() => {
            copyResultBtn.innerHTML = originalText;
        }, 2000);
    });
    
    // URL Discovery Tab 
    const fetchUrlsBtn = document.getElementById('fetch-urls-btn');
    const waybackUrl = document.getElementById('wayback-url');
    const urlsResults = document.getElementById('urls-results');
    const urlsCount = document.getElementById('urls-count');
    
    fetchUrlsBtn.addEventListener('click', fetchUrlsFromMultipleSources);
    
    async function fetchUrlsFromMultipleSources() {
        const domain = extractDomain(waybackUrl.value.trim());
        if (!domain) {
            alert('Please enter a valid domain (e.g., example.com)');
            return;
        }

        fetchUrlsBtn.disabled = true;
        fetchUrlsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Searching...';
        urlsResults.innerHTML = `
            <div class="url-status">
                <i class="fas fa-info-circle"></i>
                <div class="url-status-text">Discovering URLs for ${domain} from multiple sources...</div>
                <div class="loading-spinner"></div>
            </div>
        `;

        try {
            const [waybackUrls, commonUrls] = await Promise.all([
                fetchWaybackUrls(domain),
                fetchCommonUrls(domain)
            ]);

            const allUrls = [...new Set([...waybackUrls, ...commonUrls])];
            
            if (allUrls.length === 0) {
                urlsResults.innerHTML = `
                    <div class="url-status">
                        <i class="fas fa-exclamation-circle"></i>
                        <div class="url-status-text">No URLs found for ${domain}</div>
                    </div>
                `;
                urlsCount.textContent = '0';
                return;
            }

            displayUrlResults(allUrls, domain);

        } catch (error) {
            console.error('Error fetching URLs:', error);
            urlsResults.innerHTML = `
                <div class="url-status">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div class="url-status-text">Error: ${error.message}</div>
                </div>
            `;
            urlsCount.textContent = '0';
        } finally {
            fetchUrlsBtn.disabled = false;
            fetchUrlsBtn.innerHTML = '<i class="fas fa-spider"></i> Discover URLs';
        }
    }

    function extractDomain(input) {
        if (!input) return '';
        
        let domain = input.replace(/^(https?:\/\/)?(www\.)?/, '');
        domain = domain.split('/')[0];
        domain = domain.split('?')[0];
        domain = domain.split('#')[0];
        
        const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
        return domainRegex.test(domain) ? domain : '';
    }

    async function fetchWaybackUrls(domain) {
        try {
            const response = await fetch(`https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=original&collapse=urlkey&limit=500`);
            
            if (!response.ok) {
                throw new Error(`Wayback Machine API error: ${response.status}`);
            }
            
            const data = await response.json();
            return data && data.length > 1 ? data.slice(1).map(row => row[0]) : [];
        } catch (error) {
            console.error('Wayback Machine fetch error:', error);
            return [];
        }
    }

    async function fetchCommonUrls(domain) {
        const commonPaths = [
            'admin', 'login', 'wp-admin', 'wp-login', 'administrator',
            'api', 'graphql', 'rest', 'v1', 'v2',
            'config', 'env', '.env', 'config.php', 'configuration',
            'backup', 'backups', 'dump', 'sql', 'database',
            'test', 'dev', 'stage', 'staging', 'beta',
            'phpinfo', 'info.php', 'status', 'health',
            'git', '.git', 'svn', '.svn', 'cvs',
            'aws', 's3', 'storage', 'bucket'
        ];

        const urls = commonPaths.map(path => `https://${domain}/${path}`);
        
        const extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.json',
            '.xml', '.txt', '.conf', '.config', '.ini',
            '.sql', '.bak', '.tar', '.gz', '.zip'
        ];
        
        extensions.forEach(ext => {
            urls.push(`https://${domain}/index${ext}`);
            urls.push(`https://${domain}/main${ext}`);
            urls.push(`https://${domain}/config${ext}`);
        });
        
        return urls;
    }

    function displayUrlResults(urls, domain) {
        urlsResults.innerHTML = '';
        urlsCount.textContent = urls.length;

        const filters = [
            { name: 'All', filter: () => true, icon: 'fa-globe' },
            { name: 'Admin', filter: url => url.match(/admin|login|dashboard|panel|manager|control/i), icon: 'fa-user-shield' },
            { name: 'API', filter: url => url.match(/api|rest|graphql|v[0-9]|endpoint/i), icon: 'fa-code' },
            { name: 'Config', filter: url => url.match(/config|\.env|setting|configuration|\.(php|asp|aspx|jsp)$/i), icon: 'fa-cog' },
            { name: 'Files', filter: url => url.match(/\.(json|xml|txt|sql|bak|tar|gz|zip)$/i), icon: 'fa-file' },
            { name: 'Interesting', filter: url => url.match(/backup|dump|test|dev|stage|git|svn|aws|s3|bucket/i), icon: 'fa-search-plus' }
        ];

        const filtersHtml = filters.map(filter => `
            <button class="filter-btn" data-filter="${filter.name.toLowerCase()}">
                <i class="fas ${filter.icon}"></i> ${filter.name}
            </button>
        `).join('');

        urlsResults.innerHTML = `
            <div class="url-status">
                <i class="fas fa-check-circle"></i>
                <div class="url-status-text">Found ${urls.length} URLs for ${domain}</div>
            </div>
            <div class="url-filters">
                ${filtersHtml}
            </div>
            <div id="urls-list-container"></div>
        `;

        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');

                const filterName = this.getAttribute('data-filter');
                const filter = filters.find(f => f.name.toLowerCase() === filterName);
                renderFilteredUrls(urls, filter.filter);
            });
        });

        document.querySelector('.filter-btn').classList.add('active');
        renderFilteredUrls(urls, filters[0].filter);
    }

    function renderFilteredUrls(allUrls, filterFn) {
        const filteredUrls = allUrls.filter(filterFn);
        const urlsListContainer = document.getElementById('urls-list-container');

        if (!filteredUrls.length) {
            urlsListContainer.innerHTML = `
                <div class="empty-state" style="height: 100px;">
                    <i class="fas fa-search"></i>
                    <p>No URLs match the current filter</p>
                </div>
            `;
            return;
        }

        const itemsPerPage = 20;
        let currentPage = 1;
        const totalPages = Math.ceil(filteredUrls.length / itemsPerPage);

        function renderPage(page) {
            currentPage = page;
            const startIndex = (page - 1) * itemsPerPage;
            const endIndex = Math.min(startIndex + itemsPerPage, filteredUrls.length);
            const pageUrls = filteredUrls.slice(startIndex, endIndex);

            const urlsHtml = pageUrls.map(url => {
                let icon = 'fa-link';
                if (url.match(/admin|login/i)) icon = 'fa-user-shield';
                else if (url.match(/api|rest/i)) icon = 'fa-code';
                else if (url.match(/config|\.env/i)) icon = 'fa-cog';
                else if (url.match(/\.(php|asp|aspx|jsp)$/i)) icon = 'fa-file-code';
                else if (url.match(/\.(json|xml|txt|sql)$/i)) icon = 'fa-file-alt';
                
                return `
                    <div class="url-item">
                        <i class="fas ${icon}"></i>
                        <a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>
                        <button class="copy-url-btn" data-url="${url}" title="Copy URL">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                `;
            }).join('');

            let paginationHtml = '';
            if (totalPages > 1) {
                paginationHtml = `
                    <div class="url-pagination">
                        ${currentPage > 1 ? `<button class="page-btn" data-page="${currentPage - 1}"><i class="fas fa-chevron-left"></i></button>` : ''}
                        
                        ${Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                            const pageNum = i + 1;
                            if (totalPages <= 5 || pageNum === 1 || pageNum === totalPages || 
                                (pageNum >= currentPage - 1 && pageNum <= currentPage + 1)) {
                                return `<button class="page-btn ${pageNum === currentPage ? 'active' : ''}" data-page="${pageNum}">${pageNum}</button>`;
                            } else if (pageNum === currentPage - 2 || pageNum === currentPage + 2) {
                                return `<span class="page-dots">...</span>`;
                            }
                            return '';
                        }).join('')}
                        
                        ${currentPage < totalPages ? `<button class="page-btn" data-page="${currentPage + 1}"><i class="fas fa-chevron-right"></i></button>` : ''}
                    </div>
                `;
            }

            urlsListContainer.innerHTML = `
                <div class="urls-list">
                    ${urlsHtml}
                </div>
                ${paginationHtml}
            `;

            document.querySelectorAll('.page-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const pageNum = parseInt(this.getAttribute('data-page'));
                    if (!isNaN(pageNum)) renderPage(pageNum);
                });
            });

            document.querySelectorAll('.copy-url-btn').forEach(btn => {
                btn.addEventListener('click', async function() {
                    const url = this.getAttribute('data-url');
                    try {
                        await navigator.clipboard.writeText(url);
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="fas fa-check"></i>';
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                        }, 2000);
                    } catch (error) {
                        console.error('Copy failed:', error);
                    }
                });
            });
        }

        renderPage(1);
    }

    // Header Analyzer Tab (unchanged from your original implementation)
    const analyzeHeadersBtn = document.getElementById('analyze-headers-btn');
    const headersInput = document.getElementById('headers-input');
    const headersResults = document.getElementById('headers-results');
    
    analyzeHeadersBtn.addEventListener('click', () => {
        const headersText = headersInput.value.trim();
        if (!headersText) {
            alert('Please paste HTTP headers');
            return;
        }
        
        const headers = {};
        const lines = headersText.split('\n');
        
        lines.forEach(line => {
            if (line.trim() === '') return;
            const separator = line.indexOf(':');
            if (separator === -1) return;
            
            const name = line.substring(0, separator).trim();
            const value = line.substring(separator + 1).trim();
            headers[name] = value;
        });
        
        analyzeHeaders(headers);
    });
    
    function analyzeHeaders(headers) {
        headersResults.innerHTML = '';
        
        if (Object.keys(headers).length === 0) {
            headersResults.innerHTML = '<div class="log-entry">No valid HTTP headers found</div>';
            return;
        }
        
        const securityHeaders = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ];
        
        securityHeaders.forEach(header => {
            const headerItem = document.createElement('div');
            headerItem.className = 'header-item';
            
            if (headers[header]) {
                headerItem.innerHTML = `
                    <div class="header-name">
                        ${header}
                        <span class="header-status status-good">PRESENT</span>
                    </div>
                    <div class="header-value">${headers[header]}</div>
                `;
            } else {
                headerItem.innerHTML = `
                    <div class="header-name">
                        ${header}
                        <span class="header-status status-bad">MISSING</span>
                    </div>
                    <div class="header-value">This important security header is missing</div>
                `;
            }
            
            headersResults.appendChild(headerItem);
        });
        
        Object.keys(headers).forEach(header => {
            if (!securityHeaders.includes(header)) {
                const headerItem = document.createElement('div');
                headerItem.className = 'header-item';
                headerItem.innerHTML = `
                    <div class="header-name">${header}</div>
                    <div class="header-value">${headers[header]}</div>
                `;
                headersResults.appendChild(headerItem);
            }
            });
            }
            });
         