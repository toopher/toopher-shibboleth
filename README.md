Toopher Shibboleth
===========

Shibboleth Multi-Context Broker Toopher Authentication.  This is a plugin for the 
[Shibboleth Multi-Context Broker](https://wiki.shibboleth.net/confluence/display/SHIB2/Multi-Context+Broker). 
It provides support for [Toopher](http://www.toopher.com/) second factor authentication.

Requirements
============

This module requires at least multi-context-broker-1.1.3.jar or later.

Email Reset Attribute
--------------------

One of the configuration steps will require an attribute coming from your resolver that contains an authoritative email address
for which to send reset email in the event the user loses their device.  This attribute can be multi-valued, but the Toopher
MCB sub-module will only choose the first address in the returned set as the address to use for the reset link.  It is *required*
that you do *not* protect that email account with Toopher


# Installation
1. Copy the jar files to your shibboleth-source-dir/lib.  
2. run install.sh
3. Copy and skin the *toopher.vm* file to the directory holding the rest of your MCB velocity templates

# Configuration

## mcb-spring.xml

Before you begin you must create a requester in the Toopher admin panel.  Then edit the *mcb-spring.xml* file and add the following block.

    <bean id="mcb.toopher" class="com.toopher.shibboleth.mcb.ToopherLoginSubmodule">
        <!-- consumer key -->
        <constructor-arg index="0" value="CONSUMER_KEY_GOES_HERE" />
        <!-- consumer secret -->
        <constructor-arg index="1" value="CONSUMER SECRET GOES HERE" />
        <!-- Should we require the user to enter their Challenge drawing enter true or false -->
        <constructor-arg index="2" value="false" />
        <!-- Should the user not be allowed to use automation?  true here means disable automation for the user & require them to press the button -->
        <constructor-arg index="3" value="false" />
        <!-- The attribute coming from your attribute resolver that contains an email address which Toopher will send reset links to if 
	the user loses their device -->
        <constructor-arg index="4" value="attribute that contains reset email address" />
	<!-- what velocity template holds our UI -->
        <constructor-arg index="5" value="toopher.vm" />
    </bean>

*Optional* 

If you are not using Toopher's Cloud Service offering and have an on-premises toopher server add an addtional `<constructor-arg>` to the bean

    <constructor-arg index="6" value="http://my.toopher.server/" />


Next you need to edit the *mcb.Configuration* bean and add a 

    <ref bean="mcb.toopher" />

## multi-context-broker.xml

Next you need to edit the *multi-context-broker.xml* file and add the toopher method to the authmethods:

    <method name="toopher" bean="mcb.toopher">
            Toopher
    </method> 

Next, map it to a context in the authnContexts block:

     <context name="toopher" method="toopher">
                <allowedContexts>
                </allowedContexts>
        </context>

### Note: you need to ensure that you do NOT specify Toopher as a default initial context.  In order to function, the user must already have established their identity to the MCB via another context.

## handler.xml

Finally, edit the *handler.xml* file and add the Toopher context to the list of contexts that the MCB handles.

     <AuthenticationMethod>toopher</AuthenticationMethod>

## logging.xml

To activate logging for the Toopher module, add this to your `logging.xml`.

    <logger name="com.toopher.shibboleth">
        <level value="INFO" />
    </logger> 

Using Multiple Options
======================

The configuration of this module allows for setting various options that control how the user interacts with the
Toopher client on their mobile device.  It is recommended that if you want your services to take advantage of requiring
the user to use or not use automation and/or force the user to enter their challenge code, that you create multiple
authenction contexts each mapped to an indiviudal invocation of the Toopher MCB module with the varying options.  Each
invocation of the module should share the same consumer key and secret so the user is not forced to re-pair their device
for each varying invocation of the module.

Building From Source
====================

To build the module from source, you first have to download and build the Shibboleth Multi Context Broker from <https://github.com/Internet2/Shibboleth-Multi-Context-Broker>.  Once you have 
that built and in your local Maven repository, then you can build this module via `mvn package`.
