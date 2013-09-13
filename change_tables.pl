#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;
use Firewall::Audit qw/subnet2range/;

print "THIS  CCCHANGEEE TABLE SE\n";

sub change_tables{
    my $t_id=shift;
    	
    #change fp-address to cfg_net
    change_net($t_id);
    #change fp-address_group to cfg_net_grp
    change_net_grp($t_id);
    #change fp-service to cfg_defser_grp
    change_defser($t_id);
    #change fp-service_group to cfg_ser_grp
    change_ser_grp($t_id);
    #change fp-policy to cfg_acl  
		change_acl($t_id);
    #change fp-policy to cfg_acl_obj
    change_acl_obj($t_id);
    #save "count" in four tables
    save_count($t_id);

    print "all of the tables are transformed\n";
    print "ok\n";
    
}

sub change_net{
    #change fp-address to cfg_net
    my $tid = shift;
    my $dbh = open_db;
    my $sth=$dbh->prepare("SELECT STRING,VALUE FROM `fp-address` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        my @arr = split /\s+/,$row_ary[1];
        my @new_arr = ();
        foreach my $net_ip (@arr){  # "$net_ip" could be only one form
            if ( $net_ip =~ /(.*\/\d*)(<.*>)/ ){   #subnet with breakpoint change into form of range
                $net_ip = subnet2range($1).($2);
            }elsif( $net_ip =~ /(.*\/\d*)/ ){   #subnet without breakpoint
                $net_ip = subnet2range($net_ip);
            }   #change of subnet finished
            if ($net_ip eq '0.0.0.0-255.255.255.255'){  #store as 'any'  
                $net_ip = 'any';
            }
            push @new_arr,$net_ip;
        }
        my $net = join ' ',@new_arr;
        #store present net object in table of cfg_net
        my $sth_net = $dbh->prepare(qq/INSERT INTO cfg_net (task_id, net_name, net_ip) 
                                    VALUES ("$tid", "$row_ary[0]", "$net")/)
        or die "prepare failed:".$dbh->errstr();
        $sth_net->execute() or die $!;
        $sth_net->finish();           
    }

    print "cfg_net finished\n";
    $sth->finish();
    $dbh->disconnect;
}

sub change_net_grp{
    #change fp-address_group to cfg_net_grp
    my $tid = shift;
    my $dbh = open_db;
    my $sth = $dbh->prepare("SELECT STRING,VALUE FROM `fp-address_group` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        #print "group $row_ary[0]**************************\n";
        my @member = split /\s+/,$row_ary[1];
#        print @member."\n";
        my @net_grp_ip=();
        foreach my $mem (@member){  #each mem is a net object or a net group(in USG firewall)
            #print $mem."\n";
            if ($mem =~ /any/i){
                push @net_grp_ip,'any';
                next;
            } 
            
            my $sth1 = $dbh->prepare(qq/SELECT net_ip FROM cfg_net WHERE net_name=\'$mem\' and task_id=$tid/)
            or die "prepare failed:".$dbh->errstr();
            $sth1->execute() or die $!;
            while (my @row_ary1=$sth1->fetchrow_array()) {  #in this case, mem is a net object
                #print "$mem is a net object\n";
                push @net_grp_ip,$row_ary1[0];
                next;
            }
            
            my $sth2 = $dbh->prepare(qq/SELECT net_ip FROM cfg_net_grp WHERE net_grp_name=\'$mem\' and task_id=$tid/)
            or die "prepare failed:".$dbh->errstr();
            $sth2->execute() or die $!;
            while (my @row_ary2=$sth2->fetchrow_array()) {  #in this case, mem is a net group
                #print "$mem is a net group\n";
                push @net_grp_ip,$row_ary2[0];
            }
        }
        my $net_grp = join ' ',@net_grp_ip;
        #store present net group in table of cfg_net_grp
        my $sth_net_grp = $dbh->prepare(qq/INSERT INTO cfg_net_grp (task_id, net_grp_name,net_member,net_ip) 
                                        VALUES ("$tid","$row_ary[0]","$row_ary[1]","$net_grp")/)
        or die "prepare failed:".$dbh->errstr();
        #print "########$row_ary[0] is inserted#########\n";
        $sth_net_grp->execute() or die $!;
        my $sth_re = $dbh->prepare("FLUSH TABLE cfg_net_grp")
            or die "prepare failed:".$dbh->errstr();
        $sth_re->execute() or die $!;
        $sth_re->finish();
        $sth_net_grp->finish();

    }

    print "cfg_net_grp finished\n";
    $sth->finish();
    $dbh->disconnect;
}

sub change_defser{
    #change fp-service to cfg_defser_grp
    my $tid = shift;
    my $dbh = open_db;
    
    #get serveices in table of fp-service
    my $sth=$dbh->prepare("SELECT STRING,VALUE FROM `fp-service` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        #print"=================$row_ary[0]================\n";
        #get each service
        #need  service name, service type value (and destination ports for tcp/udp/icmp)
        #type value of tcp:6    udp:17   icmp:1
        #each service may include several protocols, seperated by ' '
        my @ser_arr = split /\s+/,$row_ary[1];  #get each portocol
        foreach my $ser (@ser_arr){
            my @arr = split /\//,$ser;   #split protocol and port
            my @dst_port;   #destination ports
            my $ser_type;   #type value
            if ($arr[0] ~~ /tcp|udp/){  # $arr[0] is the protocol
                print "a tcp/udp service.\n";
                my @ports = split /:/,$arr[1];  #split source ports and destination ports
                @dst_port = split /-/,$ports[1]; #split destination ports  
                if ($arr[0] ~~ 'tcp'){
                    $ser_type = 6;   #tcp
                }else{
                    $ser_type = 17;  #udp
                }           
            }elsif ($arr[0] ~~ /icmp/){
                #print "a icmp service\n";
                $ser_type = 1;  #icmp
                @dst_port = split /:/,$arr[1];
            }else {
                #print "other protocol\n";   #ok
                $ser_type = $arr[1];    #other portocol
                #print "$arr[1]\n";
                @dst_port = qw/0 0/;
            }
            #store present service in table of cfg_defser_grp
            my $sth_ser = $dbh->prepare(qq/INSERT INTO cfg_defser_grp 
                                        (task_id,   defsrv_name,    defsrv_type,    defsrv_from_port,   defsrv_to_port) VALUES 
                                        ("$tid",    "$row_ary[0]",  "$ser_type",    "$dst_port[0]",     "$dst_port[1]")/)
            or die "prepare failed:".$dbh->errstr();
            $sth_ser->execute() or die $!;
            $sth_ser->finish();    
        }   #foreach                  
    }   #while

    print "cfg_defser_grp finished\n";
    $sth->finish();
    $dbh->disconnect;
}

sub change_ser_grp{
    #change fp-service_group to cfg_ser_grp
    my $tid = shift;
    my $dbh = open_db;
    my $sth=$dbh->prepare("SELECT STRING,VALUE FROM `fp-service_group` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        #store present service group in table of cfg_ser_grp
        my $sth_ser = $dbh->prepare(qq/INSERT INTO cfg_ser_grp (task_id, ser_grp_name, ser_member) 
                                    VALUES ("$tid", "$row_ary[0]", "$row_ary[1]")/)
        or die "prepare failed:".$dbh->errstr();
        $sth_ser->execute() or die $!;
        $sth_ser->finish();              
    }

    print "cfg_acl_obj finished\n";
    $sth->finish();
    $dbh->disconnect;
}

sub change_acl{
    #change fp-policy to cfg_acl
    my $tid = shift;
    my $dbh = open_db;

    #NAME--acl_id;  ACTION--acl_policy; SRC_IF--interface;  SRC_IP--src_addr;   DST_IP--dst_addr
    #SERVICE--srv;  STATUS--policy_state;   GROUP--acl_grp
   
    my $sth=$dbh->prepare(qq/ SELECT NAME,ACTION,SRC_IF,SRC_IP,DST_IP,SERVICE,SCHEDULE,`GROUP`,STATUS from `fp-policy` WHERE tid=$tid /)
        or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){  #one acl policy
        
        my $src_addr;   #source ip for one acl policy
        my @src_arr = ();
        my $dst_addr;   #destination ip for one acl policy
        my @dst_arr = ();
        my @srcip_arr = split /\s+/,$row_ary[3];    #array of all the source address objects
        my @dstip_arr = split /\s+/,$row_ary[4];    #array of all the destination address objects
        #print "\n\n****************************$row_ary[0],\tsrcip_arr:\t$srcip_arr[0]\n";
        #get source ip from name of address objects(net object or a net group)
        LINE: foreach my $srcip (@srcip_arr){
                #print "srcip:".$srcip."---\n";
                # }
            if ($srcip ~~ /any/){
                print "this is a any\n";
                push @src_arr,'any';
                next LINE;
            }
#            print "@@@@@";
            my $sign_src = 0;
            #if srcip is one net object
            my $src_net = $dbh->prepare("SELECT VALUE FROM `fp-address` WHERE STRING=\'$srcip\' and tid=$tid")
            or die "prepare failed:".$dbh->errstr();
            $src_net->execute() or die $!;
            while (my @net_ip=$src_net->fetchrow_array()) {
                #print "get a net object\n";
                push @src_arr,$net_ip[0];
                $sign_src = 1;
                next LINE;
            }
            $src_net->finish();
            if ($sign_src == 1){
                next LINE;
            }
            #if srcip is one net group
            my $src_netgrp = $dbh->prepare("SELECT net_ip FROM cfg_net_grp WHERE net_grp_name=\'$srcip\' and task_id=$tid")
            or die "prepare failed:".$dbh->errstr();
            $src_netgrp->execute() or die $!;
            while (my @netgrp_ip = $src_netgrp->fetchrow_array()) {
                #print "get a net group\n";
                push @src_arr,$netgrp_ip[0];
            }
        }
        $src_addr = join ' ',@src_arr;
#        print $src_addr."@@@\n";
       
        #get destination ip from name of address objects(net object or a net group)
        LINES: foreach my $dstip (@dstip_arr){
                #print "dstip:".$dstip."---\n";
                # }
            if ($dstip ~~ /any/){
                #print "this is a any\n";
                push @dst_arr,'any';
                next LINES;
            }
#            print "@@@@@";
            my $sign_dst = 0;
            #if dstip is one net object
            my $dst_net = $dbh->prepare("SELECT VALUE FROM `fp-address` WHERE STRING=\'$dstip\' and tid=$tid")
            or die "prepare failed:".$dbh->errstr();
            $dst_net->execute() or die $!;
            while (my @net_ip=$dst_net->fetchrow_array()) {
                #print "get a net object\n";
                push @dst_arr,$net_ip[0];
                $sign_dst = 1;
                next LINES;
            }
            $dst_net->finish();
            if ($sign_dst == 1){
                next LINES;
            }
            #if dstip is one net group
            my $dst_netgrp = $dbh->prepare("SELECT net_ip FROM cfg_net_grp WHERE net_grp_name=\'$dstip\' and task_id=$tid")
            or die "prepare failed:".$dbh->errstr();
            $dst_netgrp->execute() or die $!;
            while (my @netgrp_ip = $dst_netgrp->fetchrow_array()) {
                #print "get a net group\n";
                push @dst_arr,$netgrp_ip[0];
            }
        }
        $dst_addr = join ' ',@dst_arr;
#        print $dst_addr."@@@\n";

#        #if acl group is undefined,save as default
        my $acl_grp;
        if (defined $row_ary[7]){
            $acl_grp = 'row_ary[7]';
        }else{
            $acl_grp = 'default';
        }

        #change ACTION into numbers
        #if action is ssl_vpn or ,save as 3
        my $acl_policy;
        if($row_ary[1] eq 'permit'){
            $acl_policy = 1;
        }elsif ($row_ary[1] eq 'deny'){
            $acl_policy = 0;
        }else{
            $acl_policy = 3;    #3 is just a sign
        }
				
				#get policy status
				my $status;
				if ($row_ary[8] eq 'enable') {
						$status = 1;
				}else {
						$status = 0;
				}

        #store present acl policy in table of cfg_acl
        my $sth_acl = $dbh->prepare(qq/ INSERT INTO cfg_acl 
                                        (   task_id,    acl_id,     acl_grp,    acl_policy, 
                                            src_addr,   dst_addr,   srv,
                                            interface,  schedule,   policy_state   ) 
                                    VALUES (    "$tid",     "$row_ary[0]",  "$acl_grp",  "$acl_policy",
                                                "$src_addr", "$dst_addr",   "$row_ary[5]",
                                                "$row_ary[2]",  "$row_ary[6]",  "$status"   )/)
        or die "prepare failed:".$dbh->errstr();
        $sth_acl->execute() or die $!;
        $sth_acl->finish();           

    }

    print "cfg_acl finished\n";
    $sth->finish();
    $dbh->disconnect;
}

sub change_acl_obj{
    #change fp-policy to cfg_acl_obj
    my $tid = shift;
    my $dbh = open_db;
    my $sth=$dbh->prepare("SELECT NAME,SRC_IP,DST_IP,SERVICE FROM `fp-policy` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
        #get dev_id
        my $dev_id;
        my $sth_dev = $dbh->prepare("SELECT dev_id FROM sig_task_dev WHERE task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth_dev->execute() or die $!;
        while (my @row_dev=$sth_dev->fetchrow_array()) {
            #print "policy $row_ary[0] get its dev_id:$row_dev[0]\n";
            $dev_id = $row_dev[0]
        }
        $sth_dev->finish();
        
        #store present acl policy in table of cfg_acl_obj
        my $sth_obj = $dbh->prepare(qq/INSERT INTO cfg_acl_obj 
                                    (   task_id,    dev_id, acl_id,
                                        src_ip,     dst_ip, srv ) 
                                    VALUES 
                                    (   "$tid",         "$dev_id",      "$row_ary[0]",  
                                        "$row_ary[1]",  "$row_ary[2]",  "$row_ary[3]")/)
        or die "prepare failed:".$dbh->errstr();
        $sth_obj->execute() or die $!;
        $sth_obj->finish();             
    }

    print "cfg_acl_obj finished\n";
    $sth->finish();
    $dbh->disconnect;
}

#save field "count"
sub save_count{
    #change fp-address to cfg_net
    my $tid = shift;
    my $dbh = open_db;

    #=============
    #table:cfg_net 
    my $sth_net=$dbh->prepare("SELECT net_name FROM cfg_net WHERE task_id=$tid")
    or die "prepare failed:".$dbh->errstr();
    $sth_net->execute() or die $!;
    while(my @net = $sth_net->fetchrow_array()){  #name of each net object
        my $count = 0;
        my $sth_acl = $dbh->prepare("SELECT src_ip,dst_ip FROM cfg_acl_obj WHERE task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth_acl->execute() or die $!;
        while (my @acl_ary=$sth_acl->fetchrow_array()) {
            #print $acl_ary[0].' '.$acl_ary[1]."\n";
            my @srcip = split /\s+/,$acl_ary[0]; #array of source ip object 
            my @dstip = split /\s+/,$acl_ary[1]; #array of destination ip object
#            print "$row_ary[1]\n"; 
#            foreach (@dstip){
#                print "$_\n"
#            }
            my %hash_acl = ();
            foreach (@srcip){
                $hash_acl{$_} = 1;    
            }
            foreach (@dstip){
                    #print "$_\n";
                $hash_acl{$_} = 1;
            }
            if (exists $hash_acl{$net[0]}){
                $count++;
            }
        }
        #print $row_ary[0].':'.$count."\n";
        $sth_acl->finish();   
        #store "count"
        my $sth = $dbh->prepare("UPDATE cfg_net SET count=$count WHERE net_name=\'$net[0]\' AND task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth->execute() or die $!;
        $sth->finish();     
    }
    $sth_net->finish();
    #print "cfg_net count finished\n";
    #end of talbe : cfg_net

    #=================
    #table:cfg_net_grp 
    my $sth_net_grp=$dbh->prepare("SELECT net_grp_name FROM cfg_net_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth_net_grp->execute() or die $!;

    while(my @net_grp = $sth_net_grp->fetchrow_array()){  #name of each net object
        my $count = 0;
        my $sth_acl = $dbh->prepare("SELECT src_ip,dst_ip FROM cfg_acl_obj WHERE task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth_acl->execute() or die $!;
        while (my @acl_ary=$sth_acl->fetchrow_array()) {
            #print $acl_ary[0].' '.$acl_ary[1]."\n";
            my @srcip = split /\s+/,$acl_ary[0]; #array of source ip object 
            my @dstip = split /\s+/,$acl_ary[1]; #array of destination ip object
#            print "$row_ary[1]\n"; 
#            foreach (@dstip){
#                print "$_\n"
#            }
            my %hash_acl = ();
            foreach (@srcip){
                $hash_acl{$_} = 1;    
            }
            foreach (@dstip){
                    #print "$_\n";
                $hash_acl{$_} = 1;
            }
            if (exists $hash_acl{$net_grp[0]}){
                $count++;
            }
        }
        #print $row_ary[0].':'.$count."\n";
        $sth_acl->finish();  
        #store "count"
        my $sth = $dbh->prepare("UPDATE cfg_net_grp SET count=$count WHERE net_grp_name=\'$net_grp[0]\' AND task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth->execute() or die $!;
        $sth->finish();     
    }
    $sth_net_grp->finish();
    #print "cfg_net_grp count finished\n";  
    #end of talbe : cfg_net

    #====================
    #table:cfg_defser_grp
    my $sth_defser=$dbh->prepare("SELECT defsrv_name FROM cfg_defser_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth_defser->execute() or die $!;

    while(my @defser = $sth_defser->fetchrow_array()){  #name of each net object
        my $count = 0;
        my $sth_acl = $dbh->prepare("SELECT srv FROM cfg_acl_obj WHERE task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth_acl->execute() or die $!;
        while (my @acl_ary=$sth_acl->fetchrow_array()) {
            #print $acl_ary[0].' '.$acl_ary[1]."\n";
            my @srv = split /\s+/,$acl_ary[0]; #array of source ip object                
            my %hash_acl = ();
            foreach (@srv){
                $hash_acl{$_} = 1;    
            }
            if (exists $hash_acl{$defser[0]}){
                $count++;
            }
        }
        $sth_acl->finish(); 
        #print $defser[0].':'.$count."\n";          
        #store "count"
        my $sth = $dbh->prepare("UPDATE cfg_defser_grp SET count=$count WHERE defsrv_name=\'$defser[0]\' AND task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth->execute() or die $!;
        $sth->finish();     
    }
    $sth_defser->finish();
    #print "cfg_defser_grp count finished\n"; 
    #end of talbe : cfg_defser_grp

    #================
    #table:cfg_ser_grp
    my $sth_ser=$dbh->prepare("SELECT ser_grp_name FROM cfg_ser_grp WHERE task_id=$tid")
    or die "prepare failed:".$dbh->errstr();
    $sth_ser->execute() or die $!;

    while(my @ser = $sth_ser->fetchrow_array()){  #name of each net object
        my $count = 0;
        my $sth_acl = $dbh->prepare("SELECT srv FROM cfg_acl_obj WHERE task_id=$tid")
            or die "prepare failed:".$dbh->errstr();
        $sth_acl->execute() or die $!;
        while (my @acl_ary=$sth_acl->fetchrow_array()) {
            #print $acl_ary[0].' '.$acl_ary[1]."\n";
            my @srv = split /\s+/,$acl_ary[0]; #array of source ip object                
            my %hash_acl = ();
            foreach (@srv){
                $hash_acl{$_} = 1;    
            }
            if (exists $hash_acl{$ser[0]}){
                $count++;
            }
        }
        $sth_acl->finish(); 
        #print $ser[0].':'.$count."\n";          
        #store "count"
        my $sth = $dbh->prepare("UPDATE cfg_ser_grp SET count=$count WHERE ser_grp_name=\'$ser[0]\' AND task_id=$tid")
        or die "prepare failed:".$dbh->errstr();
        $sth->execute() or die $!;
        $sth->finish();     
    }
    $sth_ser->finish();
    #print "cfg_ser_grp count finished\n"; 
    #end of talbe : cfg_ser_grp     
    print "save_count finished\n";

    $dbh->disconnect;
}

change_tables shift @ARGV;
#change_tables 6;
1
