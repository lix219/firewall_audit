#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;


sub _2001 {

   #2001:detect telnet ip_limit
    #pass 2001:ip_limited
    #fail 2001:no ip limit
    
    my $tid=shift;
		my $sign_2001 = 0;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT srv_status,srv_ip FROM cfg_srv WHERE srv_type=0 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";

        if($row_ary[0]==0){
                pass $tid,2001,'ignore','telnet未开启，此项不需审计';
								$sign_2001 = 1;
        }else{
						if ($row_ary[1]=0){
                pass $tid, 2001,'fail', 'telnet连接未设置IP限制';
								$sign_2001 = 1;     
						}
        }
    }
    if ($sign_2001 == 0){
            pass $tid, 2001,'pass', "telnet连接设置了IP限制";
    }
		print "OK\n";
    $sth->finish();
}

#_2001 99513;
1
