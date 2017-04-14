# bouncycastle-maven-plugin

This project provides a Maven plugin for generating PGP signature files for project artifacts using [BouncyCastle](https://www.bouncycastle.org/).

## Overview

This plugin provides the same functionality as the [maven-gpg-plugin](http://maven.apache.org/plugins/maven-gpg-plugin) when executing the [gpg:sign](http://maven.apache.org/plugins/maven-gpg-plugin/sign-mojo.html) goal. The only difference in functionality is that this plugin does not rely upon GPG (or another command line utility) which allows us to provide PGP keys and passphrases via Maven properties.  As a result, your cryptographic material does not have to exist on the build server's disk.

## Usage

In order to use this plugin add the following to your `pom.xml` file:

```xml
<plugin>
    <groupId>com.deciphernow</groupId>
    <artifactId>bouncycastle-maven-plugin</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <configuration>
        <passphrase>${env.PGP_PASSPHRASE}</passphrase>
        <rings>${env.PGP_RINGS}</rings>
        <userId>${env.PGP_USER_ID}</userId>
    </configuration>
    <executions>
        <execution>
            <id>sign-artifacts</id>
            <phase>verify</phase>
            <goals>
                <goal>sign</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

## Building

This build uses standard Maven build commands but assumes that the following are installed and configured locally:

1) Java (1.8 or greater)
1) Maven (3.0 or greater)

## Contributing

1. Fork it
1. Create your feature branch (`git checkout -b my-new-feature`)
1. Commit your changes (`git commit -am 'Add some feature'`)
1. Push to the branch (`git push origin my-new-feature`)
1. Create new Pull Request
 