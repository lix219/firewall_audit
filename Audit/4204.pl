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
    my @arr_1=@{$net_hash_4204{$net_1}};
    #print "$#arr_1\t"; 
    my @arr_2=@{$net_hash_4204{$net_2}};
    #print "$#arr_2\n";

    my %hash_1;
    my %hash_2;

    foreach(@arr_1){
       $hash_1{$_}=1;
    }

#    foreach(@arr_2){
#        #print "AB";
#        $hash_2{$_}=1;
#    }

#    foreach(@arr_1){
#        if( !(exists $hash_2{$_}) ){    #two members are different 
#            return 0;
#        }
#    }
    foreach(@arr_2){
        if( (exists $hash_1{$_}) ){    #two members have same ip 
            return 0;
        }
    }

    return 1;    #two members are the same
}

sub _4204{
    #detect net group redundancy in itself
    #same net/net group in one net group  

    my $tid=shift;
    my $dbh = open_db;
	my $sign_4204=0;

    my $sth=$dbh->prepare("SELECT net_grp_name,net_member FROM cfg_net_grp WHERE task_id=$tid")
       or die "prepare failed:".$dbh->errstr();
    $sth->execute() or die $!;   
    our %net_hash_4204 = ();
    #my @net_grp;
    while(my @row_ary=$sth->fetchrow_array()){
        my @mem_ary=split(/\s+/,$row_ary[1]);   #in both topsec and USG firewalls, name of net object and net group can't be the same 
        foreach my $mem(@mem_ary){
            my @arr=();   
            my @iparr = (); #to store ip of each member

            my $sth1=$dbh->prepare("SELECT net_ip FROM cfg_net WHERE net_name=\'$mem\' and task_id=$tid")  
                or die "prepare failed:".$dbh->errstr();
            $sth1->execute() or die $!;
            while(my @row_ary1=$sth1->fetchrow_array()){    #in this case, member is net object                
                @arr = split /\s+/,$row_ary1[0];
            }
            $sth1->finish();

            my $sth2=$dbh->prepare("SELECT net_ip FROM cfg_net_grp WHERE net_grp_name=\'$mem\' and task_id=$tid")
                or die "prepare failed:".$dbh->errstr();
            $sth2->execute() or die $!;
            while (my @row_ary2=$sth2->fetchrow_array()) {
                @arr = split /\s+/,$row_ary2[0];
            }
            $sth2->finish();
                    foreach my $net_ip(@arr){
                        if($net_ip =~ /any/i){  #any
                            push @iparr,1;
                            next;
                        }
                        if(!($net_ip =~ /-/)){
                            #print "单个ip $net_ip\n";
                            push (@iparr,$net_ip);                    
                            next;
                        }

                        if(!($net_ip =~ /</)){
                            if ($net_ip =~ /(.*)-(.*)/){                            
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
                        #next;   #                          
                    }   #each net_ip
    #        if (@iparr){
    #            #my @iparr
    #            my %count_hash = ();
    #            my @uniq_array = ();    #remove redundant ip
    #            foreach my $value ( @iparr ){
    #                if ( exists($count_hash{$value}) ){
    #                    next;
    #                } 
    #                else{
    #                    $count_hash{ $value } = 1;
    #                    push( @uniq_array, $value );
    #                }
    #            }
    #            $net_hash_4204{$mem}=\@uniq_array;
    #        }
        if (@iparr) {$net_hash_4204{$mem} = \@iparr;}
    
        }   #get ip of each member 
    
        #compare the members
        my @array;
        foreach my $key (keys %net_hash_4204) {
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
                my $ret = compare_ip($array[$i],$array[$j]);    #0:have same ip     1:completely different   

                if($ret == 0){
                    #print "$array[$i]和$array[$j]写到数据库\n";
                    pass $tid,4204,'fail',"地址组$row_ary[0]内部成员$array[$i]和$array[$j]冗余";
                    $sign_4204=1;
                }
                $j++;
            }
            shift @array;
        }
    }   #end of each net group audit

    if($sign_4204 == 0){pass $tid,4204,'pass',"地址对象组内没有冗余的地址对象";}


    print "ok\n";
    $sth->finish();

  
}   

#_4204 2015;
1
