<h3>REPLACE DOWNLOAD</h3>
<h4>Intercept Target download and replace it with Spoof file.</h4>
<h4>Basic Stuff:</h4>
<ol>
    <li>Enable port forwarding (1) just in case you want to remote.
        <br/> It doesn't seem to make a difference.
    </li>
    <li>
        Set ALL iptables - INPUT, OUTPUT, FORWARD. 
        <br />
        There is not conflict local vs remote.
    </li>
    <li>This only works with arp_spoof.py, which sets you onPath.
    <br />
    Or, PitM (Person in the Middle) hehe.
    </li>
    <li>
        Flush ip_tables when your finished. 
        <br/>
        But I sometimes just leave them running, this is my attack machine.
        <br />
        And it's a VM after all.
    </li>
    <li></li>
</ol>
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