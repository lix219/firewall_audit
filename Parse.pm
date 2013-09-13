package Firewall::Parse;

use strict;

our (@ISA, @EXPORT_OK, $VERSION);

BEGIN {
    require Exporter;

    @ISA       = qw /Exporter/;
    @EXPORT_OK = qw /parse parse2/;
    $VERSION   = '1.0102';
}

use Firewall::Common qw /record open_db/;

my (
    $digit,     $alpha,     $hex,       $period,    $sp,
    $begin,     $sq,        $digits,    $token,     $tokens,
    $ipaddr,    $ipaddrs,   $macaddr,   $comment
);

$digit    =  '[0-9]';
$alpha    =  '[A-Za-z]';
$hex      =  '[0-9A-Fa-f]';
$period   =  '[.]';
$sp       =  '[ ]';
$begin    =  '\A';
$sq       =  "[']";

use utf8;
$digits   =  "$digit*";
# $token    =  "$alpha(?:$alpha|$digit|[-]|[_]|[.])*";
#$token    =  "(?:$alpha|$digit|[-]|[_]|[.]|[\u4e00-\u9fa5]|[\X]|[\p{Han}])*";
#$token    =  "\\X*";
#$token    =  "\X*";
#$token    =  "\p{Han}*";
$token    =  "\\S*";
$tokens   =  "(?:$token $sp)+?";

$ipaddr   =  "$digits [.] $digits [.] $digits [.] $digits";
$ipaddrs  =  "(?:$ipaddr $sp)+?";
$macaddr  =  "$hex* [:] $hex* [:] $hex* [:] $hex* [:] $hex* [:] $hex*";

$comment  =  ".+?";

my %RE = (

    define_area => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp area $sp add $sp

        name $sp (?<name> $token)
        ($sp attribute $sp $sq (?<attribute> $tokens) $sq)?
        ($sp access $sp (?<access> (on|off)))?

        ($sp comment $sp $sq (?<comment> $comment) $sq)?

    }xi,

    define_host => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp host $sp add $sp

        name $sp (?<name> \S+)
        ($sp ipaddr $sp $sq (?<ipaddr> $ipaddrs) $sq)?
        ($sp macaddr $sp (?<macaddr> $macaddr))?

        ($sp session $sp (?<session> $digits))?
        ($sp halfsession $sp (?<halfsession> $digits))?
        ($sp synproxy $sp (?<synproxy> on|off))?
        ($sp vsid $sp (?<vsid> $digits))?
        ($sp mss $sp (?<mss> $digits))?
        ($sp dir $sp (?<mss> src|dst))?
        ($sp session-per-second $sp (?<sessionpersecond> $digits))?

    }xi,

    define_range => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp range $sp add $sp

        name $sp (?<name> $token) $sp
        ip1 $sp (?<ip1> $ipaddr) $sp
        ip2 $sp (?<ip2> $ipaddr)
        ($sp except $sp $sq (?<except> $ipaddrs) $sq)?

        ($sp session $sp (?<session> $digits))?
        ($sp synproxy $sp (?<synproxy> on|off))?
        ($sp vsid $sp (?<vsid> $digits))?
        ($sp mss $sp (?<mss> $digits))?
        ($sp dir $sp (?<mss> src|dst))?
        ($sp session-per-second $sp (?<sessionpersecond> $digits))?

    }xi,

    define_subnet => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp subnet $sp add $sp

        name $sp (?<name> $token) $sp
        ipaddr $sp (?<ipaddr> $ipaddr) $sp
        mask $sp (?<mask> $ipaddr)
        ($sp except $sp $sq (?<except> $ipaddrs) $sq)?

        ($sp session $sp (?<session> $digits))?
        ($sp synproxy $sp (?<synproxy> on|off))?
        ($sp vsid $sp (?<vsid> $digits))?
        ($sp mss $sp (?<mss> $digits))?
        ($sp dir $sp (?<mss> src|dst))?
        ($sp session-per-second $sp (?<sessionpersecond> $digits))?

    }xi,

    define_service => qr{
        # Add on July 3
        $begin
        id $sp (?<id> $digits) $sp
        define $sp service $sp add $sp

        name $sp (?<name> $token) $sp
        protocol $sp (?<protocol> $digits) $sp
        port $sp (?<port> $digits)
        ($sp port2 $sp (?<port2> $digits))?

        ($sp vsid $sp (?<vsid> $digits))?
        ($sp comment $sp $sq (?<comment> $comment) $sq)?

    }xi,

    define_groupaddress => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp group_address $sp add $sp

        name $sp (?<name> $token)
        ($sp member $sp $sq (?<member> $tokens) $sq)?

        ($sp vsid $sp (?<vsid> $digits))?

    }xi,

    define_groupservice => qr{

        $begin
        id $sp (?<id> $digits) $sp
        define $sp group_service $sp add $sp

        name $sp (?<name> $token)
        ($sp member $sp $sq (?<member> $tokens) $sq)?

        ($sp vsid $sp (?<vsid> $digits))?

    }xi,

    firewall_grouppolicy => qr{

        $begin
        id $sp (?<id> $digits) $sp
        firewall $sp group-policy $sp add $sp

        name $sp (?<name> $token)

        ($sp before $sp (?<before> $digits))?
        ($sp vsid $sp (?<vsid> $digits))?

    }xi,

    firewall_policy => qr{

        $begin
        id $sp (?<id> $digits) $sp
        firewall $sp policy $sp add $sp

        action $sp (?<action> accept|deny|collect)

        ($sp srcarea $sp $sq (?<srcarea> $tokens) $sq)?
        ($sp dstarea $sp $sq (?<dstarea> $tokens) $sq)?
        ($sp srcvlan $sp $sq (?<srcvlan> $tokens) $sq)?
        ($sp dstvlan $sp $sq (?<dstvlan> $tokens) $sq)?
        ($sp src $sp $sq (?<src> $tokens) $sq)?
        ($sp dst $sp $sq (?<dst> $tokens) $sq)?
        ($sp service $sp $sq (?<service> $tokens) $sq)?
        ($sp schedule $sp $sq (?<schedule> $tokens) $sq)?
        ($sp sport $sp $sq (?<sport> $tokens) $sq)?
        ($sp orig_dst $sp $sq (?<origdst> $tokens) $sq)?
        ($sp dpi $sp $sq (?<dpi> $tokens) $sq)?
        
        ($sp permament $sp (?<permament> on|off))?
        ($sp log $sp (?<log> on|off|alarm))?
        ($sp enable $sp (?<enable> yes|no))?

        ($sp before $sp (?<before> $digits))?
        ($sp vsid $sp (?<vsid> $digits))?

        # there may be some wrong
        ($sp group-name $sp (?<groupname> $token))?
        ($sp comment $sp $sq (?<comment> $comment) $sq)?

        ($sp srcrole $sp $sq (?<srcrole> $tokens) $sq)?
        ($sp max-active-session $sp $sq (?<maxactivesession> $tokens) $sq)?
        ($sp ids $sp $sq (?<ids> $tokens) $sq)?
        ($sp original-dscp $sp $sq (?<originaldscp> $tokens) $sq)?
        ($sp target-dscp $sp $sq (?<targetdscp> $tokens) $sq)?

        ($sp cos $sp (?<cos> $digits))?
        ($sp anti-proxy $sp (?<antiproxy> on|off))?
        ($sp qos $sp $sq (?<qos> $tokens) $sq)?

        ($sp ips-up $sp $sq (?<ipsup> $tokens) $sq)?
        ($sp ips-down $sp $sq (?<ipsdown> $tokens) $sq)?

        ($sp traffic-statistic $sp (?<trafficstatistic> on|off))?
        ($sp dns $sp $sq (?<dns> $tokens) $sq)?

    }xi,

    nat_policy => qr{

        $begin
        id $sp (?<id> $digits) $sp
        nat $sp policy $sp add $sp

        ($sp srcarea $sp $sq (?<srcarea> $tokens) $sq)?
        ($sp dstarea $sp $sq (?<dstarea> $tokens) $sq)?
        ($sp srcvlan $sp $sq (?<srcvlan> $tokens) $sq)?
        ($sp dstvlan $sp $sq (?<dstvlan> $tokens) $sq)?

        ($sp orig_src $sp $sq (?<origsrc> $tokens) $sq)?
        ($sp orig_dst $sp $sq (?<origdst> $tokens) $sq)?
        ($sp orig_sport $sp $sq (?<origsport> $tokens) $sq)?

        ($sp orig_service $sp $sq (?<origservice> $tokens) $sq)?
        ($sp trans_src $sp $sq (?<transsrc> $tokens) $sq)?
        ($sp trans_dst $sp $sq (?<transdst> $tokens) $sq)?
        ($sp trans_service $sp $sq (?<transservice> $tokens) $sq)?

        ($sp vsid $sp (?<vsid> $digits))?
        ($sp pat $sp (?<pat> yes|no))?
        ($sp enable $sp (?<enable> yes|no))?
        ($sp before $sp (?<before> $digits))?

        ($sp comment $sp $sq (?<comment> $comment) $sq)?

    }xi,

    authset_timeout => qr{
        system $sp authset $sp timeout $sp
        set $sp num $sp (?<num> $digits)
    }xi,

    authset_managermaxlogin => qr{
        system $sp authset $sp managermaxlogin $sp
        set $sp maxnum $sp (?<maxnum> $digits)
    }xi,

    authset_maxonlineadm => qr{
        system $sp authset $sp maxonlineadm $sp
        set $sp maxnum $sp (?<maxnum> $digits)
    }xi,

    authset_passwdpolicy => qr{
        system $sp authset $sp passwd-policy $sp
        set-manager $sp policy $sp (?<policy> weak|medium|strong)
    }xi,

    system_telnetd => qr{
        system $sp telnetd $sp (?<telnetd> start|stop)
    }xi,

    system_sshd => qr{
        system $sp sshd $sp (?<sshd> start|stop)
    }xi,

    system_httpd => qr{
        system $sp httpd $sp (?<httpd> start|stop)
    }xi,

    webui_idletimeout => qr{
        system $sp webui $sp
        idle-timeout $sp (?<idletimeout> $digits)
    }xi,

    pf_telnet => qr{

        $begin
        id $sp (?<id> $digits) $sp
        pf $sp service $sp add $sp name $sp telnet $sp
        area $sp (?<area> $token) $sp
        addressname $sp (?<addressname> $token)

    }xi,

    pf_ssh => qr{

        $begin
        id $sp (?<id> $digits) $sp
        pf $sp service $sp add $sp name $sp ssh $sp
        area $sp (?<area> $token) $sp
        addressname $sp (?<addressname> $token)

    }xi,

    pf_sslvpnmgr => qr{

        $begin
        id $sp (?<id> $digits) $sp
        pf $sp service $sp add $sp name $sp sslvpnmgr $sp
        area $sp (?<area> $token) $sp
        addressname $sp (?<addressname> $token)

    }xi,

);

my %SI = (

);

# Follow subrountines head by store_ is will to store parse informations

sub store_acl {

    my $h = shift;
    my @p  = @_;

    my $sth = $h->prepare(qq/INSERT INTO cfg_acl (`task_id`, acl_id, acl_grp, acl_policy, src_addr, dst_addr, srv, policy_state, schedule, interface) VALUES ("$p[0]","$p[1]","$p[2]","$p[3]","$p[6]","$p[8]","$p[9]","$p[10]","$p[13]","$p[12]")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_acl";
    record 'PARSE', "cfg_acl: @p";
    $sth->finish;
}

sub store_users {

    my $h = shift;
    my @p = @_;

    my $sth = $h->prepare(qq/INSERT INTO cfg_dev_users (task_id, m_login, m_online, pwd) VALUES ("$p[0]","$p[1]","$p[2]","$p[3]")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_dev_users";
    record 'PARSE', "cfg_dev_user: @p";
    $sth->finish;
}

sub store_srv {

    my $h = shift;
    my @p = @_;

    my $sth = $h->prepare(qq/INSERT INTO cfg_srv (task_id, srv_type, srv_status, timeout, srv_ip) VALUES ("$p[0]","$p[1]","$p[2]","$p[3]","$p[4]")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_srv";
    record 'PARSE', "cfg_cfg_srv: @p";
    $sth->finish;
}

sub store_acl_grp {

    my $h = shift;
    my $t = shift;
    my $p = shift;

    my $sth = $h->prepare(qq/INSERT INTO cfg_acl_grp (task_id, grp_name) VALUES ("$t","$p")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_acl_grp";
    $sth->finish;
}

sub store_define_grp {

    my $h = shift;
    my $t = shift;
    my $s = shift;
    my $p = shift;
    my $q = shift;

    my $sth;

    $sth = $h->prepare(qq/INSERT INTO cfg_net (task_id, net_name, net_ip, sign) VALUES ("$t","$p","$q","0")/) if $s eq 'host';
    $sth = $h->prepare(qq/INSERT INTO cfg_net (task_id, net_name, net_ip, sign) VALUES ("$t","$p","$q","1")/) if $s eq 'range';
    $sth = $h->prepare(qq/INSERT INTO cfg_net (task_id, net_name, net_ip, sign) VALUES ("$t","$p","$q","2")/) if $s eq 'subnet';
    $sth = $h->prepare(qq/INSERT INTO cfg_ser_grp (task_id, ser_grp_name, ser_member) VALUES ("$t","$p","$q")/) if $s eq 'ser';
    $sth = $h->prepare(qq/INSERT INTO cfg_net_grp (task_id, net_grp_name, net_ip) VALUES ("$t","$p","$q")/) if $s eq 'net';

    $sth->execute or record 'DBASE', "execute sql fail in cfg_host_grp";
    record 'PARSE', "cfg_host/range/subnet: $s $p $q";
    $sth->finish;
}

sub store_defser {

    my $h = shift;
    my @p = @_;

    my $sth = $h->prepare(qq/INSERT INTO cfg_defser_grp (task_id, defsrv_name, defsrv_type, defsrv_from_port, defsrv_to_port) VALUES ("$p[0]","$p[1]","$p[2]","$p[3]","$p[4]")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_defser";
    record 'PARSE', "cfg_defser_grp: @p";
    $sth->finish;
}

# TODO
sub save_shitis {

    my $h = shift;
    my @p = @_;

    my $sth = $h->prepare(qq/INSERT INTO cfg_acl_obj (task_id, acl_id, src_ip, dst_ip, srv) VALUES ("$p[0]","$p[1]","$p[2]","$p[3]","$p[4]")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_defser";
    record 'PARSE', "cfg_defser_grp: @p";
    $sth->finish;
}

sub save_opt {

    my $h = shift;
    my $ta = shift;
    my $aclid = shift;
    my $line = shift;

    my $sth = $h->prepare(qq/INSERT INTO cfg_opt (task_id, acl_id, cfg) VALUES ("$ta","$aclid","$line")/);

    $sth->execute or record 'DBASE', "execute sql fail in cfg_defser";
    $sth->finish;
}
sub replace {

    my $text = shift;
    my %res  = @_;

    foreach (keys %res) {
        $text =~ s/$_ /$res{$_}/g;
    }

    return $text;
}

sub sub_net {
    my $ipaddr = shift;
    my $mask   = shift;

    my (@msk, @nsk);
    @msk = split /\./, $mask;
    $nsk[$_] = 255 - $msk[$_] foreach (0..3);
    my $nask = join '.', @nsk;

    my (@ip1, @ip2);
    push @ip1, int((split /\./, $ipaddr)[$_]) & int((split /\./, $mask)[$_]) foreach (0..3);
    push @ip2, int((split /\./, $ipaddr)[$_]) | int((split /\./, $nask)[$_]) foreach (0..3);

    my $ip1 = join '.', @ip1;
    my $ip2 = join '.', @ip2;

    my $range = "$ip1-$ip2";
    return $range;
}

# Start parse from here ...

sub parse {

    my $conf_path = shift;
    my $task_id   = shift;

    open CONF, '<:encoding(UTF-8)', $conf_path or record "OPENS", "open $conf_path fail!!!!!";

    record 'PARSE', "begin a new parse, task id: $task_id";

    my (%area, %host, %service, %address, %range, %subnet, @group, %policy, %defservice);
    my @users = ($task_id, '', '', '');

    my @t_srv = ($task_id, '0', '', '', '1');
    my @s_srv = ($task_id, '1', '1', '', '1');
    my @w_srv = ($task_id, '2', '1', '', '1');

    # $count is a variable for counting line number of command
    my $count = 1;
    my $ph = open_db;

    while (my $line = <CONF>) {

        if ($line =~ $RE{define_area}) {
            my %b = %+;
            $area{$b{name}} = $b{attribute};
        }
        elsif ($line =~ $RE{define_host}) {
            print "$line";
            my %b = %+;
            $host{$b{name}} = $b{ipaddr};
            print "=$b{name}=";
            print "\n";
            use Smart::Comments;
            ### %b
        }
        elsif ($line =~ $RE{define_groupservice}) {
            my %b = %+;
            $service{$b{name}} = $b{member};
        }

        elsif ($line =~ $RE{define_groupaddress}) {
            my %b = %+;
            $address{$b{name}} = $b{member};
        }

        elsif ($line =~ $RE{define_range}) {
            my %b = %+;
            chop $b{except};
            $b{except} =~ s/ /:/g;
            if ($b{ip1} eq $b{ip2}) {
                $range{$b{name}} = "$b{ip1} ";
            }
            else {
                $range{$b{name}} = "$b{ip1}-$b{ip2}<$b{except}> ";
                $range{$b{name}} =~ s/0.0.0.0-255.255.255.255<>/any/g;
                $range{$b{name}} =~ s/<>//g;
            }
            record 'PARSE', "parse range: $range{$b{name}}";
        }
        elsif ($line =~ $RE{define_subnet}) {
            my %b = %+;
            my $c = sub_net $+{ipaddr}, $+{mask};
            chop $b{except};
            $b{except} =~ s/ /:/g;
            $subnet{$b{name}} = "$c<$b{except}> ";
            $subnet{$b{name}} =~ s/<>//g;
            record 'PARSE', "parse subnet: $subnet{$b{name}}";
        }

        elsif ($line =~ $RE{firewall_grouppolicy}) {
            my %b = %+;
            push @group, $b{name};
        }

        elsif ($line =~ $RE{firewall_policy}) {
            my %b = %+;

            $b{srcarea} = 'any ' if $b{srcarea} eq '';
            $b{src}     = 'any ' if $b{src}     eq '';
            $b{sport}   = 'any ' if $b{sport}   eq '';
            $b{dst}     = 'any ' if $b{dst}     eq '';
            $b{service} = 'any ' if $b{service} eq '';

            $b{enable}  = 'yes'  if $b{enable}  eq '';
            $b{log}     = 'off'  if $b{log}     eq '';

            $b{groupname} = 'default ' if $b{groupname} eq '';
            $b{schedule} = 'always ' if $b{schedule} eq '';

            $policy{$count} = "$task_id,$b{id},$b{groupname},$b{action},$b{srcarea},$b{dstarea},$b{src},$b{sport},$b{dst},$b{service},$b{enable},$b{log},$b{srcarea},$b{schedule}";

            record 'PARSE', "parse policy: $policy{$count}";
            my @shifts = ($task_id, $b{id}, $b{src}, $b{dst}, $b{service});
            save_shitis $ph, @shifts;
            save_opt $ph, $task_id, $b{id}, $line;
        }

        elsif ($line =~ $RE{authset_managermaxlogin}) {
            $users[1] = $+{maxnum};
        }

        elsif ($line =~ $RE{authset_maxonlineadm}) {
            $users[2] = $+{maxnum};
        }

        elsif ($line =~ $RE{authset_passwdpolicy}) {
            $users[3] = $+{policy};
        }

        elsif ($line =~ $RE{system_telnetd}) {
            $t_srv[2] = 1 if $+{telnetd} eq 'start';
            $t_srv[2] = 0 if $+{telnetd} eq 'stop';
        }

        elsif ($line =~ $RE{pf_telnet}) {
            $t_srv[4] = 0 if $+{addressname} =~ /any/;
        }

        elsif ($line =~ $RE{system_sshd}) {
            $s_srv[2] = 1 if $+{sshd} eq 'start';
            $s_srv[2] = 0 if $+{sshd} eq 'stop';
        }

        elsif ($line =~ $RE{pf_ssh}) {
            $s_srv[4] = 0 if $+{addressname} =~ /any/;
        }

        elsif ($line =~ $RE{webui_idletimeout}) {
            $w_srv[3] = $+{idletimeout};
        }

        elsif ($line =~ $RE{pf_sslvpnmgr}) {
            $w_srv[4] = 0 if $+{addressname} =~ /any/;
        }

        elsif ($line =~ $RE{define_service}) {
            my %b = %+;
            $b{port2} = $b{port} if $b{port2} eq '';
            $defservice{$b{name}} = "$task_id,$b{name},$b{protocol},$b{port},$b{port2}";
            record 'PARSE', "parse defservice: $defservice{$b{name}}";
        }

        $count++;
        record 'PARSE', "scanf next line";

    }

    record 'PARSE', "scanf $conf_path finished";


    record 'PARSE', "prepare to write data";

    # Prepare to write data to mysql


print "$RE{define_range}";

    foreach (keys %policy) {

        $policy{$_} = replace $policy{$_}, %area;
        $policy{$_} = replace $policy{$_}, %address;
        $policy{$_} = replace $policy{$_}, %host;
#        $policy{$_} = replace $policy{$_}, %area;
        $policy{$_} = replace $policy{$_}, %range;
        $policy{$_} = replace $policy{$_}, %subnet;
        $policy{$_} = replace $policy{$_}, %service;

        # Use numbers to replace words in db
        $policy{$_} =~ s/accept/1/g;
        $policy{$_} =~ s/deny/0/g;
        $policy{$_} =~ s/collect/2/g;
        $policy{$_} =~ s/yes/1/g;
        $policy{$_} =~ s/no/0/g;

        my @p = split ',', $policy{$_};

        store_acl $ph, @p;
    }

    store_users $ph, @users;

    store_srv $ph, @t_srv;
    store_srv $ph, @s_srv;
    store_srv $ph, @w_srv;


    foreach (@group) {
        store_acl_grp $ph, $task_id, $_;
    }

    foreach (keys %address) {
        $address{$_} = replace $address{$_}, %host;
        $address{$_} = replace $address{$_}, %range;
        $address{$_} = replace $address{$_}, %subnet;
    }


    store_define_grp $ph, $task_id, 'host', $_, $host{$_} foreach (keys %host);
    store_define_grp $ph, $task_id, 'range', $_, $range{$_} foreach (keys %range);
    store_define_grp $ph, $task_id, 'subnet', $_, $subnet{$_} foreach (keys %subnet);
    store_define_grp $ph, $task_id, 'net', $_, $address{$_} foreach (keys %address);
    store_define_grp $ph, $task_id, 'ser', $_, $service{$_} foreach (keys %service);

    store_defser $ph, split ',', $defservice{$_} foreach (keys %defservice);

    record 'DBASE', "task id: $task_id store finished";
    record 'PARSE', "task id: $task_id parse finished";
    return 0;
}

sub parse2 {
    my $conf_path = shift;
    my $task_id   = shift;

    open CONF, '<', $conf_path or record "OPENS", "open $conf_path fail!!!!!";

    record 'PARSE', "begin a new parse, task id: $task_id";
    while (my $line = <CONF>) {

    }
    record 'DBASE', "task id: $task_id store finished";
    record 'PARSE', "task id: $task_id parse finished";
    return 0;
}

1;

__END__


=head1 NAME

Firewall::Parse - Parse the firewall configure file

=head1 SYNOPSIS

  use Firewall::Parse qw /parse/;

  parse $conf_path, $task_id;

=head1 DESCRIPTION

This Module give a interface that allow you to parse the firewall configure
file, and the result will store using hash.

=cut
