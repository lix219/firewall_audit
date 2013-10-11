#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub _2003 {

   #2003:detect web_manage ip_limit
    #pass 2003:ip_limited
    #fail 2003:no ip limit
    
    my $tid=shift;
		my $sign_2003 = 0;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT srv_ip FROM cfg_srv WHERE srv_type=2 and srv_status=1 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";
				if(!defined($row_ary[0])){
						return 1;
				}
        if ($row_ary[0]==0){
						pass $tid, 2003,'fail', 'web管理界面未设置IP限制';     
						$sign_2003 == 1;
				}
    }
   	if ($sign_2003 ==0){ 
        pass $tid, 2003,'pass', 'Web管理界面设置IP限制';
		}
    print "OK\n";
    $sth->finish();
}

#_2003 1025;
1
