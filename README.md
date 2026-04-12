<h3>REPLACE DOWNLOAD</h3>
<h4>Intercept a download and replace it with my own file.</h4>
<h4>I guess it will work locally but let's see remote</h4>
<h4>Create iptables queue for input and output</h4>
<p>sudo iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass</p>
<p>sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass</p>
<p>
    <b>
        <a href="https://en.wikipedia.org/wiki/List_of_HTTP_status_codes">
            List of HTTP Status codes:
        </a>
    </b>
</p>
<p>We want to use 301 to tell our response packet it is being redirected.</p>
<h4>Run on a remote computer</h4>
<ol>
<li><b>Remove previous iptables:</b>iptables --flush</li>
<li><b>iptables</b>: set our queue to FORWARD
<p>sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass</p>
</li>
<li><b>arp_spoof</b>: Get in the middle onPath attack.</li>
<li><b>Start webserver locally</b>: service apache2 start</li>
<li>
<b>Webroot:<b>Location of where webfiles are stored: 
/var/www/html/
</li>
</ol>