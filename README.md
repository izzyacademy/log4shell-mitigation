## Details and Mitigation Strategy for log4j2 Security Vulnerability

This is a quick post on the mitigation for CVE-2021-44228 Security Vulnerability aka Log4Shell and LogJam found in log4j2

## What It Is

It is a Zero-day exploit that is in the form of an RCE (remote code execution) that is present in certain versions of the popular java logging framework log4j2

## How Serious is it?

It is rated 10 out of 10 on the Common Vulnerability Scoring System (CVSS) scale

## When it was Discovered?

The vulnerability was reported by Alibaba Cloud's security team to Apache on November 24 and was discovered by Chen Zhaojun of Alibaba Cloud Security Team

It was then [disclosed publicly](https://twitter.com/P0rZ9/status/1468949890571337731) via the log4j project’s [GitHub](https://github.com/apache/logging-log4j2/pull/608) on December 9, 2021

## How Does it Work?

Running applications that use the logging library become vulenarable if it uses user specify input that is not sanitized to remotely.

When the applications processes the log events with the user provided string, the vulnerable system could then download and run a malicious code from an attacker-controlled domain, effectively taking over the vulnerable application.

## Who is Affected?

The vulnerability impacts Apache Log4j 2 versions from 2.0-beta9 to 2.14.1 if you have introduced these two dependencies:

- log4j-api
- log4j-core

It is not present in version 1 of log4j

JDK versions greater than 6u211, 7u201, 8u191, and 11.0.1 are not affected by the LDAP attack vector. 

Why is this the case? Well, this is because in these JDK versions the property com.sun.jndi.ldap.object.trustURLCodebase is set to false

As a result, the JNDI cannot load remote code using LDAP.

Popular Apache Software Foundation projects such as Apache Software Foundation, such as:
- Apache Struts
- Apache Flink
- Apache Druid
- Apache Flume
- Apache Solr
- Apache Flink
- Apache Kafka
- Apache Dubbo
- and may be many more could be affected as well.

Other open source projects outside the ASF such as Redis, ElasticSearch and Logstash could also be affected.

## What you need to do

1. If you are using the affected versions, immediately upgrade to log4j v2.15

2. If you are using log4j v2.10 or above, and are currently unable to immediately upgrade, then change the system property:

```bash

log4j2.formatMsgNoLookups=true

```

3. You can also delete the JndiLookup class from the classpath:

```bash

zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class

```

This command will remote the class from the log4j-core*.jar file 

Stay tuned for additional updates.

If you have any questions, please feel free to reach out.

Thanks

## References
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://logging.apache.org/log4j/2.x/download.html

