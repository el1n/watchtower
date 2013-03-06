#!/usr/bin/perl
use 5.10.0;
use vars qw();
use constant ME =>"Watchtower";
use constant VERSION =>"1.0.2";
use constant LOG_LINE =>20;
use constant MON_LINE =>1;
use constant PING_TIMEOUT =>0.5;
use constant MON_TIMEOUT =>43200;
use constant ACT_SCH_WAIT =>10;
use constant PSV_SCH_WAIT =>180;
use constant PSV_SCH_DELAY =>0.333;
use constant ACT_MON_WAIT =>5;
use List::MoreUtils qw(:all);
use Time::HiRes qw(sleep);
use threads;
use threads::shared;
use Thread::Queue;
use Net::Ping;
#use Net::CIDR;
use Net::CIDR::Set;
use Curses;
#use Win32::Console;

my $que = Thread::Queue->new();
#(my $ech = Net::Ping->new($> ? "udp" : "icmp"))->hires();
#(my $syn = Net::Ping->new("syn"))->hires();

threads->new(sub{
	do{
		map{$que->enqueue([1,(split(/\s+/,$_))[0,2]])}grep(!/(?:^Address|incomplete)/,`arp -n`);
	}while(sleep(ACT_SCH_WAIT));

	return();
})->detach();

if(open(FH,"binoculars.conf")){
	while(<FH>){
		chomp();

		if(/^(\d+(?:\.\d+){3})(?:\/(\d+))?$/){
			threads->new(sub{
				my $addr = shift();
				my $mask = shift();
				(my $ech = Net::Ping->new($> ? "udp" : "icmp"))->hires();
				do{
					my $n = 2 ** (32 - $mask) - 1;
					my $i = unpack("N",pack("C4",split(/\./,$addr))) & ~$n;
					for($i..$i + $n){
						if($ech->ping(join(".",unpack("C4",pack("N",$_))),PING_TIMEOUT)){
							$que->enqueue([1,join(".",unpack("C4",pack("N",$_))),undef]);
						}
						sleep(PSV_SCH_DELAY);
					}
				}while(sleep(PSV_SCH_WAIT));
			
				$ech->close();
				return();
			},$1,$2 // 32)->detach();
		}else{
		}
	}
	close(FH);
}

initscr();
start_color();
init_pair(1,COLOR_WHITE,COLOR_BLACK);
init_pair(2,COLOR_BLUE,COLOR_BLACK);
init_pair(3,COLOR_RED,COLOR_BLACK);
init_pair(4,COLOR_YELLOW,COLOR_BLACK);
logging("%s - %s (%d/%d/%d)",ME,VERSION,2,22,2013);

if($> != 0){
	&logging("WARNING %s running as non-root, using udp ping but it may not work.");
}

my $d;
my @order;
while(sub{
#	given(shift()){
	for(shift()){
		when(1){
			if(!defined($d->{$_[0]})){
				threads->new(sub{
					my $d = {v4a =>shift(),hwa =>shift(),u =>time(),h =>[(0) x 18]};
					(my $ech = Net::Ping->new($> ? "udp" : "icmp"))->hires();
	
					do{
						if((($d->{f},$d->{r},undef) = $ech->ping($d->{v4a},PING_TIMEOUT)) && $d->{f}){
							$d->{r} *= 1000;
							$d->{u} = time();
						}

						push(@{$d->{h}},$d->{f} ? 2 : 3);
						while($#{$d->{h}} > 17){
							shift(@{$d->{h}});
						}

						$que->enqueue([3,$d->{v4a},$d]);
					}while(($d->{u} + MON_TIMEOUT) > time() && sleep(ACT_MON_WAIT));

					$que->enqueue([2,$d->{v4a}]);
					$ech->close();
					return();
				},@_)->detach();
			}else{
				$d->{$_[0]}->{hwa} = $_[1];
			}
		}
		when(2){
			logging("%s is dead, last seen at %d:%d:%d.",$_[0],(localtime(time()))[2,1,0]);

#			splice(@order,firstidx{$_ eq $_[0]}@order,1);
			$d->{$_[0]} = undef;
		}
		when(3){
			shift();
			my $g = shift();
			my $s;
			my $e;

			for(grep{defined($g->{$_})}keys(%{$g})){
				$d->{$g->{v4a}}->{$_} = $g->{$_};
			}

			if(!grep{$_ eq $g->{v4a}}@order){
				$s = firstidx{$_ eq $g->{v4a}}@order = sort{pack("C4",split(/\./,$a)) cmp pack("C4",split(/\./,$b))}(@order,$g->{v4a});
				$e = $#order;
			}else{
				$s = firstidx{$_ eq $g->{v4a}}@order;
				$e = $s;
			}
			if((my $i = firstidx{!defined($d->{$_})}@order) != -1){
				splice(@order,$i,1);
				$s = 0;
				$e = $#order + 1;
			}

			for(my $i = 0;$i <= int(($#order + 1) / ($LINES - 1 - MON_LINE - LOG_LINE));++$i){
				addstr($y,$x + ($i * 40) + 0,"IP-Address");
				addstr($y,$x + ($i * 40) + 15,"HW-Address");
				addstr($y,$x + ($i * 40) + 34,"RTT/L");
			}
			for(my $i = $s;$i <= $e;++$i){
				my $y = int($i % ($LINES - 1 - MON_LINE - LOG_LINE)) + MON_LINE;
				my $x = int($i / ($LINES - 1 - MON_LINE - LOG_LINE)) * 40;

				if(defined($order[$i])){
					if($x != 0){
						addstr($y,$x - 1,"|");
					}
					addstr($y,$x + 0,sprintf("%-15s",$d->{$order[$i]}->{v4a}));
					addstr($y,$x + 15,sprintf("%17s",$d->{$order[$i]}->{hwa} // join(":",("--") x 6)));
					for(my $j = 0;$j < 18;++$j){
						chgat($y,$x + 15 + $j,1,undef,$d->{$order[$i]}->{h}->[$j],undef);
					}
					if($d->{$order[$i]}->{r} < 1000){
						addstr($y,$x + 34,sprintf("%3dms",$d->{$order[$i]}->{r}));
						chgat($y,$x + 34,5,undef,0,undef);
					}else{
						addstr($y,$x + 34,sprintf("%1.2fs",$d->{$order[$i]}->{r} / 1000));
						chgat($y,$x + 34,5,undef,4,undef);
					}
					if($d->{$order[$i]}->{f}){
					}else{
						addstr($y,$x + 34,sprintf("%5d",time() - $d->{$order[$i]}->{u}));
						chgat($y,$x + 0,15,undef,3,undef);
						chgat($y,$x + 34,5,undef,3,undef);
					}
				}else{
					addstr($y,$x + 0," " x 40);
					chgat($y,$x + 0,40,undef,0,undef);
				}
			}
			move($LINES,$COLS);
			refresh();
		}
		default{
			logging("WARNING Unknown function call. (%s : %s)",shift(),join(",",@_));
		}
	}
	return(1);
}->(@{($que->dequeue())[0]})){
	threads->yield();
}

sub logging
{
	move($LINES - LOG_LINE,0);
	insertln();
	addstr($LINES - LOG_LINE,0,sprintf("[%02d:%02d:%02d] ".shift(),(localtime(time()))[2,1,0],@_));
	refresh();

	return();
}

END{endwin()}
