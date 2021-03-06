#!/usr/bin/perl -I /home/fw_audit/script/lib

use Firewall::Common qw/open_db record pass/;

sub ip2num {
    my $ip = shift;
    my @p = split(/\./, $ip);

    return $p[0]* (256 ** 3) + $p[1] * 256 ** 2 + $p[2] * 256 + $p[3];
}

sub num2ip {
    my $num = shift;
    my @ip;
    my $x;
    my $i;

    for($i=0; $i<4; $i++){
      $x = $num%256;
      if($x<0) {$x += 256;}
      unshift(@ip, $x);
      $num = int($num/256);
  }

  return join('.', @ip);
}

sub compare_ip{
    $net_1=shift;
    $net_2=shift;
    #print "AA$net_1 $net_2\n";
    my @arr_1=@{$netgroup_hash{$net_1}};
    #print "$#arr_1\t"; 
    my @arr_2=@{$netgroup_hash{$net_2}};
    #print "$#arr_2\n";

    my %hash_1;
    my %hash_2;

#    foreach(@arr_1){
#       $hash_1{$_}=1;
#    }

    foreach(@arr_2){
        #print "AB";
        $hash_2{$_}=1;
    }

    foreach(@arr_1){
        if(exists $hash_2{$_}){
            return 0;
        }
    }

    return 1;

}

sub _4202{
    #detect net group redundancy
    my $tid=shift;
    my $dbh = open_db;
		my $sign_4202=0;

    my $sth=$dbh->prepare("SELECT net_grp_name,net_ip FROM cfg_net_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;

    our %netgroup_hash;
    #my @net_grp;

    while(my @row_ary=$sth->fetchrow_array()){
            #print "A@row_ary\n";
            #push @net_grp,$row_ary[0];
            my @iparr=();
            #my %netgroup_hash=;
            my @arr = split(/\s+/,$row_ary[1]); #array of net objects in present net group
            foreach my $net_ip(@arr){
                #print "test1\n";
                if($net_ip =~ /any/i){
                    #print "any\n";
                    push @iparr,1;
                    next;
                }

                if(!($net_ip =~ /-/)){
                    #print "单个ip $net_ip\n";
                    push (@iparr,$net_ip);                    
                    next;
                }

                if(!($net_ip =~ /</)){
                    if ($net_ip =~ /(.*)-(.*)/) {
                            
                            my $begin = ip2num($1);
                            my $end = ip2num($2);

                            foreach($begin..$end){                                
                                push @iparr,num2ip($_);
                            }
                    }
                    next;
                }

                if($net_ip =~ /(.*)-(.*)<(.*)>/){
                    my @break_num;
                    my @break_ip=split /:/,$3;

                    foreach my $ip(@break_ip){
                        push @break_num, (ip2num($ip) - 1);
                        push @break_num, (ip2num($ip) + 1);
                    }

                    push @break_num,ip2num($1);
                    push @break_num,ip2num($2);

                    @break_num = sort {$a <=> $b} @break_num;

                    my $a; my $b; 
                    foreach my $p (@break_num) {
                        $i++;
                        if ($i % 2 == 1) {
                        $a = $p;
                        } else {
                            $b = $p; 
                            foreach ($a..$b) {
                                push @iparr,num2ip($_);   
                            }
                        }
                    }
                }            
            } #foreach net_ip
            #my $n=$#iparr;
            #print "$n\n";
            $netgroup_hash{$row_ary[0]}=\@iparr;
    }  #while        

    my @array;
    foreach my $key (keys %netgroup_hash) {
        push @array, $key;
    }

    #my $n=$#array;
    #print "$n\n";

    my $i = 0;
    while ($i < $#array) {
        my $j = $i + 1;
        while ($j <= $#array) {
            #print $j;
            #print "\t$array[$i] $array[$j]\n";
            my $ret = compare_ip($array[$i],$array[$j]);   

            if($ret == 0){
                #print "$array[$i]和$array[$j]写到数据库\n";
                pass $tid,4202,'fail',"地址组$array[$i]和$array[$j]冗余";
								$sign_4202=1;
            }else{
                #print "why\n";
            }
            $j++;
        }
        shift @array;
    }
		if($sign_4202 == 0){pass $tid,4202,'pass',"地址组不存在冗余";}


    print "ok\n";
    $sth->finish();
}

#_4202 2015;
1
