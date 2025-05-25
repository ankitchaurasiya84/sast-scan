<h1 class="code-line" data-line-start=0 data-line-end=1 ><a id="_SASTScan__0"></a>📜 SAST-Scan 🔍</h1>
<p class="has-line-data" data-line-start="2" data-line-end="3"><a href="https://travis-ci.org/joemccann/dillinger"><img src="https://travis-ci.org/joemccann/dillinger.svg?branch=master" alt="Build Status"></a></p>
<p class="has-line-data" data-line-start="4" data-line-end="5">SAST-Scan is a lightweight, easy-to-use static application security testing (SAST) tool that helps you scan your code for vulnerabilities, providing instant feedback to improve code security! 🚀</p>
<h2 class="code-line" data-line-start=7 data-line-end=8 ><a id="Features_7"></a>Features</h2>
<pre><code>1.  Comprehensive Code Scanning – Detects a wide range of security vulnerabilities in your source code.
2.  Fast and Lightweight – Provides quick, real-time scans without affecting performance.
3.  Detailed Vulnerability Reports – Offers clear reports with fixes and line numbers for each vulnerability.
4.  Seamless Integration – Easily integrates with JavaScript frameworks like React and Node.js.
5.  Continuous Updates – Regularly updated to cover new vulnerabilities and security practices.
</code></pre>
<h2 class="code-line" data-line-start=19 data-line-end=20 ><a id="Installation_19"></a>Installation</h2>
<p class="has-line-data" data-line-start="21" data-line-end="22">You can install the package via npm:</p>
<pre><code class="has-line-data" data-line-start="24" data-line-end="26" class="language-sh">npm install sast-scan
</code></pre>
<h2 class="code-line" data-line-start=26 data-line-end=27 ><a id="Import_the_package_26"></a>Import the package:</h2>
<pre><code class="has-line-data" data-line-start="29" data-line-end="31" class="language-js"><span class="hljs-keyword">import</span> scanCode <span class="hljs-keyword">from</span> <span class="hljs-string">'sast-scan'</span>;
</code></pre>
<h1 class="code-line" data-line-start=35 data-line-end=36 ><a id="Integrate_the_scanner_into_your_project_35"></a>Integrate the scanner into your project:</h1>
<p class="has-line-data" data-line-start="38" data-line-end="39">jsx:</p>
<pre><code class="has-line-data" data-line-start="41" data-line-end="82" class="language-js">import React, { useState } from 'react';
import scanCode from 'sast-scan'; // Import your npm package

const CodeScanner = () => {
    const [code, setCode] = useState('');
    const [results, setResults] = useState([]);

    const handleScan = () => {
        let vulnerabilities = [];
        try {
            vulnerabilities = scanCode(code); // Scan the code
        } catch (error) {
            console.error(`Error scanning code: ${error.message}`);
        }
        setResults(vulnerabilities);
    };

    return (
        <div>
            <h1>Code Scanner</h1>
            <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Enter code to scan"
            />
            <button onClick={handleScan}>Scan Code</button>
            <div>
                {results.map((result, index) => (
                    <div key={index}>
                        <p> <strong>Vulnerability:</strong> {result.message}</p>
                        <p> <strong>Fix:</strong> {result.fix}</p>
                        <p> <strong>Line Number:</strong> {result.lineNumber}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default CodeScanner;
</code></pre>
<p class="has-line-data" data-line-start="83" data-line-end="84">Example Output:</p>
<pre><code class="has-line-data" data-line-start="86" data-line-end="91" class="language-sh">    •    Vulnerability: The vulnerability description
    •    Fix: Suggested fix
    •    Line Number: Line number of the issue

Note: you can refer dev.to Article for more informatation

</code></pre>
<h2 class="code-line" data-line-start=92 data-line-end=93 ><a id="License_92"></a>License</h2>
<p class="has-line-data" data-line-start="94" data-line-end="95">MIT License © 2025 [Ankit Chaurasiya]</p>
<p class="has-line-data" data-line-start="96" data-line-end="97"><strong>Ankit Chaurasiyà</strong></p>
