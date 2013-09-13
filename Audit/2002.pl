#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub _2002 {

   #2002:detect ssh ip_limit
    #pass 2002:ip_limited
    #fail 2002:no ip limit
    
    my $tid=shift;
		$sign_2002 = 0;

    my $dbh = open_db;

    my $sth=$dbh->prepare("SELECT srv_ip FROM cfg_srv WHERE srv_type=1 and srv_status=1 and task_id=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;

    while(my @row_ary=$sth->fetchrow_array()){
            
        #print "@row_ary\n";
				if ($row_ary[0]==0){
    #    		pass $tid, 2002,'pass', 'SSH连接设置IP限制' if $row_ary[0] == 1;
        		pass $tid, 2002,'fail', 'SSH连接未设置IP限制';     
						$sign_2002 = 1;
				}
    }
    if($sign_2002 == 0){
        pass $tid, 2002,'pass', 'SSH连接设置了IP限制';
		}
#		print "$sign_2002";
    print "OK\n";
    $sth->finish();
}

#_2002 99513;
1
