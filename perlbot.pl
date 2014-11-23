#!/usr/local/bin/perl

use strict;
use warnings;

use IO::Socket;
use Sys::Hostname;
use DBI;
use threads;
use threads::shared;

## Configuration ##
our %config :shared = (
    server => "irc.freenode.net",
    port => 6667,
    nick => "cercinus_",
    host => hostname(),
    realname => "Byron Grobe",
    pass => $ARGV[0]
    );

## Auxiliary Configuration ##
our %auxconfig :shared = (
    pub_ban => 1,
    pub_voice => 1,
    pub_op => 0,
    autojoin => 1,
    autovoice => 0
    );

my @autojoin = ("#barsoom", "#bsdturkey");
my @autovoice = ();


# Various Shared Variables #		

our $reload :shared = 0;

my $dbconn = DBI->connect("dbi:SQLite:dbname=users.db", "", "", { RaiseError => 1, AutoCommit => 0 });

my $socket;

our %whois :shared = (
    ident => "",
    hostmask => "",
    realname => ""
    );

open(my $log, "> /tmp/perlbot.log") or die "Could not open log: $!\n";

# sockPrint -- Outputs to the connected socket and the log file #
sub sockPrint
{
    print $socket "@_\n";
    print $log "@_\n";
}

# sockConnect -- Initializes the socket and connectes to the IRC Server #
sub sockConnect
{
    $socket = IO::Socket::INET->new(
	PeerAddr => $config{server},
	PeerPort => $config{port},
	Proto => "tcp",
	Domain => AF_INET,
	Type => SOCK_STREAM
	)
	or die "Could not connect to IRC Server: $!\n";

    $socket->autoflush(1);

    sockPrint "PASS $config{pass}";
    sockPrint "NICK $config{nick}";
    sockPrint "USER $config{nick} $config{host} $config{server} :$config{realname}";

    for(my $i=0; $i<10; $i++)
    {
	if(defined(my $in=<$socket>))
	{
	    chomp $in;
	    if($in =~ /PING/)
	    {
		(undef, my $ret) = split(/\ /, $in);
		sockPrint "PONG $ret\r";
	    }
	}
	else
	{
	    sleep 1;
	}
    }

    if($auxconfig{autojoin})
    {
	foreach my $chan (@autojoin)
	{
	    sockPrint "JOIN $chan";
	}
    }
}

# initFunc - Takes the arguments provided to many core functions and parses them into something useful #
sub initFunc
{
    my @chunks = @_;

    my $is_pm = pop(@chunks);

    (my $person, undef, my $hostmask) = split(/([!])/, $chunks[0]);
    $person =~ s/([:])//;

    my $channel = $chunks[2];
    chomp($channel);
    $channel =~ s/([:])//;

    if($is_pm)
    {
	chop($channel);
    }

    (my $ident, undef, $hostmask) = split(/([@])/, $hostmask);

    return ($person, $ident, $hostmask, $channel);

}

# autoVoice -- Handle automatically voicing people #
sub autoVoice
{
    (my $person, my $ident, my $hostmask, my $channel) = initFunc(@_, 0);

    foreach my $chan (@autovoice)
    {
	if($channel eq $chan)
	{
	    sockPrint "MODE $channel +v $person";
	}
    }
}

# addAuth -- Adds a user to the authorized users database #
sub addAuth
{
    (my $person, my $ident, my $hostmask, my $channel) = @_;

    lock( $dbconn );
    my $row = $dbconn->do("INSERT INTO USERS (IDENT, HOSTMASK) VALUES (\"$ident\", \"$hostmask\");");
    $dbconn->commit;

    if($row)
    {
	chomp $hostmask;
	sockPrint "PRIVMSG $channel :$person, $ident\@$hostmask added to authorized users database.";
    }
    else
    {
	chomp $hostmask;
	sockPrint "PRIVMSG $channel :$person, $ident\@$hostmask not added to authorized users database.";
    }
}

# checkAuth -- Checks a user against the user database #
sub checkAuth
{
    (my $ident, my $hostmask) = @_;

    lock( $dbconn );
    my $stmt = $dbconn->prepare("SELECT IDENT, HOSTMASK FROM USERS WHERE IDENT=\"$ident\" AND HOSTMASK=\"$hostmask\";");
    $stmt->execute();

    my @row = $stmt->fetchrow_array();

    $stmt->finish();

    if(@row)
    {
	return 1;
    }
    else
    {
	return 0;
    }
}

# delAuth -- Removes a user from the database #
sub delAuth
{
    (my $person, my $ident, my $hostmask, my $channel) = @_;

    lock( $dbconn );
    my $row = $dbconn->do("DELETE FROM USERS WHERE IDENT=\"$ident\" AND HOSTMASK=\"$hostmask\";");
    $dbconn->commit();

    if($row)
    {
	sockPrint "PRIVMSG $channel :$person, $ident\@$hostmask removed from authorized users database.";
    }
    else
    {
	sockPrint "PRIVMSG $channel :$person, $ident\@$hostmask not removed from authorized users database.";
    }
}

# listAuth -- Lists all the authorized users #
sub listAuth
{
    (my $person, my $ident, my $hostmask, my $channel) = initFunc(@_, 0);

    sockPrint "PRIVMSG $channel :Authorized Users";
    sockPrint "PRIVMSG $channel :Ident\tHostmask";

    lock( $dbconn );
    my $stmt = $dbconn->prepare("SELECT IDENT,HOSTMASK FROM USERS;");
    $stmt->execute();

    while( (my $ident, my $hostmask) = $stmt->fetchrow_array() )
    {
	sockPrint "PRIVMSG $channel :$ident\t$hostmask";
	sleep 1;
    }
    $stmt->finish();
}

# privateMessage -- This is called whenever the bot receives a private message #
sub privateMessage
{
    (my $person, my $ident, my $hostmask, my $channel) = initFunc(@_, 1);

    my $cmd = $_[3];
    $cmd =~ s/://;

    ($cmd, my @args) = split(/\ /, $cmd);

    # The following is support for the CTCP NOTICE command, and is required by several larger networks #
    my $tmp = $cmd;
    $tmp =~ s/\001//g;

    if ($tmp =~ /VERSION/i)
    {
	my $sysinfo = "";
	if(open(my $in, "/usr/bin/env sysinfo|"))
	{
	    $sysinfo = <$in>;
	    $sysinfo =~ s/\e\[?.*?[\@-~]//g;
	    close $in;
	}
	else
	{
	    $sysinfo = "Unable to gather system information.";
	}

	sockPrint "NOTICE $person \001VERSION perlbot-current $sysinfo Copyright (C) 2014 Byron Grobe. All Rights Reserved.\001";
    }

    # Publicly accessible commands #
    
    # Operator commands #
    if(checkAuth($ident, $hostmask))
    {
	if($cmd =~ /\.adduser/i)
	{
	    lock( %whois );
	    sockPrint "WHOIS @args";
	    cond_wait( %whois );
	    addAuth($person, $whois{ident}, $whois{hostmask}, $channel);
	}
	if($cmd =~ /\.deluser/i)
	{
	    lock( %whois );
	    sockPrint "WHOIS @args";
	    cond_wait( %whois );
	    delAuth($person, $whois{ident}, $whois{hostmask}, $channel);
	}
	if($cmd =~ /\.isauth/i)
	{
	    lock( %whois );
	    sockPrint "WHOIS @args";
	    cond_wait( %whois );
	    if(checkAuth($whois{ident},$whois{hostmask}))
	    {
		sockPrint "PRIVMSG $channel :$person, $whois{ident}\@$whois{hostmask} is an authorized user.";
	    }
	    else
	    {
		sockPrint "PRIVMSG $channel :$person, $whois{ident}\@$whois{hostmask} is not an authorized user.";
	    }
	}
    }
}

# whois -- Deals with whois information #
sub whois
{
    # When this is called, it assumes that %whois is hooked with a cond_wait #

    my @info = split(/\ /, $_[3]);
    (undef, $whois{ident}, $whois{hostmask}) = @info;

    cond_signal(%whois);
}

# sockIO -- Primary IO loop #    
sub sockIO
{
    while(defined (my $line=<$socket> ))
    {
	chop $line;
	print $log "$line\n";
	print "$line\n";
	
	my @chunks = split(/\ /, $line, 4);
	
	my $var = $chunks[1];
	chomp($var);
	
	if($var =~ /JOIN/)
	{
	    autoVoice(@chunks);
	}
	if($var =~ /PRIVMSG/)
	{
	    threads->create(\&privateMessage, @chunks);
	}
	if($var =~ /311/)
	{
	    whois(@chunks);
	}
	
    }

    if($reload)
    {
	reload();
    }
}

# reload -- completely reloads the bot #
sub reload
{
    open(my $bot, "< perlbot.sh") or die "Could not open self: $!\n";
    my @nssize = stat $bot;
    sysread $bot, my $code, $nssize[7];
    close $bot;

    eval $code;
}

# sockKeepAlive -- Sends PINGs to the IRC server to maintain the connection #
sub sockKeepAlive
{
    while(1)
    {
	sleep 60;
	sockPrint "PING $config{server}";
    }
}

# Here's what starts it all in motion #
sockConnect();

threads->create(\&sockIO);
threads->create(\&sockKeepAlive);
