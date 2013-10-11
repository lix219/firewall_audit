#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/record open_db pass/;

#venus Firewall
sub _1003 {
    #detect the admin ip limit
	my $sign_1003 = 0;
    my $tid = shift;
    my $dbh = open_db;
    my $sth = $dbh->prepare("SELECT NAME,AUTH_IP FROM `fp-auth` WHERE tid=$tid")
       or die "prepare failed:".$dbh->errstr();

    $sth->execute() or die $!;
    while(my @user_ip = $sth->fetchrow_array()){
        if ($user_ip[1] =~ /0.0.0.0\/0/) {
            pass $tid,1003,'fail',"管理员$user_ip[0]管理ip为任意";
            $sign_1003 = 1;
        }
    }

	if($sign_1003 ==0){
        pass $tid,1003,'pass',"管理员$user_ip[0]设置了管理ip";		
	}

    $sth->finish();
}

#_1003 200;
1
