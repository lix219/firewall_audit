#!/usr/bin/perl -I /home/fw_audit/script/lib
use strict;
use warnings;
use Firewall::Common qw/open_db record pass/;

#检测telnet是否开启，规则编号2000
sub _2000 {

    #2000:detect telnet status
    #pass 2000:telnet on
    #fail 2000:telnet off
    
    my $tid=shift;
		my $sign_2000 = 0;
		
    my $dbh = open_db;
		
		my $sig_dev = $dbh->prepare("SELECT dev_id FROM sig_task_dev WHERE task_id=$tid")
		or die "prepare failed:".$dbh->errstr();
		$sig_dev->execute() or die $!;
		my $dev_id = $sig_dev->fetchrow();
		
		#get dev type
		my $dev = $dbh->prepare("SELECT dev_maf FROM dev_info WHERE dev_id=\'$dev_id\'");
		$dev->execute() or die $!;
		my $dev_maf = $dev->fetchrow();
		if ($dev_maf == 1) {
				return 1;
		}


    my $sth=$dbh->prepare("SELECT srv_status FROM cfg_srv WHERE srv_type=0 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_tel=$sth->fetchrow_array()){
            
     #		print "@row_ary\n";

     #		pass $tid, 2000,'pass', "telnet远程连接未开启" if $row_ary[0] == 0;
        if($row_tel[0]==1){
						pass $tid, 2000,'fail', "telnet远程连接开启";     
						$sign_2000 = 1;
				}

    }
    if ($sign_2000 ==0){
        pass $tid, 2000,'pass', "telnet远程连接未开启";
		}
    print "OK\n";
    $sth->finish();
}

#_2000 20;
1
