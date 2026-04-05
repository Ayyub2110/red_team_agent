# Vulnerable Apache Struts (CVE-2017-5638)
# Simple servlet running on a known-vulnerable Struts2 version.
FROM tomcat:8.5-jdk8

# Download a vulnerable Struts2 showcase WAR
# Using a pre-built vulnerable app for demonstration
RUN mkdir -p /usr/local/tomcat/webapps/struts2-showcase

# Create a minimal vulnerable Struts app
COPY struts-app/ /usr/local/tomcat/webapps/ROOT/

EXPOSE 8080
CMD ["catalina.sh", "run"]
