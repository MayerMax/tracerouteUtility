<h4>Default run of the script:</h4>
<code>python traceroute.py destination</code>
<p> this utility is implemented using pure python, the idea is to make a replica
of <b>tracert</b> in Windows OS</p>
<p>however, not the same output is provided by now (as my task wasn't quite the same)<br />
during the traceroute script tries to send icmp echo packet with the <code>destination</code>
inside, than receive it and clarify some info about this ip (if it is <u>public</u>) by asking (and finding) 
correct <code>whois server</code><br />
Than output would be like this: <code>
 NETNAME, AS_POINT, COUNTRY
 </code>
 </p>
 
 <h4> Extra prerequisites</h4>
 <p><ul> 
    <li>Only under administrator mode (tested on windows)</li>
 </ul></p>
 
 <h4> Further development</h4>
 <p> probably it would be great to add an options list for users, so that they would be able
 not only to receive this particular info about ip<br />(as <code>whois</code> is internal and not ready to be used in separated mode (<font color="purple">+need some code editing</font>))
 </p>