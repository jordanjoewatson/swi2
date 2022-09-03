:- use_module(library(csv)).
:- use_module(library(lists)).

% Importing logs of CSV file, CSV file must not contain header.
% Format of CSV = unix_timestamp, src_ip, dst_ip
import_netlogs(CSV) :-
	csv_read_file(CSV, Data, [functor(netlog)]),
	maplist(assert, Data).

% Log base2 
log2(0, N) :- N is 0.
log2(X, N) :- N is (log10(X) / log10(2)).

% https://www.tek-tips.com/viewthread.cfm?qid=1604418
count([], _, 0).
count([H|T], H, N) :- 
	!, count(T, H, N1),
	N is N1 + 1.
count([_|T], G, N) :- 
	count(T, G, N).

% Calculates `Sigma [ p(valuei).log2(p(valuei)) ]`, standard entropy sum function
sigma(_, [], 0).
sigma(Ls, [H|T], E) :-
	count(Ls, H, C),
	length(Ls, L),
	F is C/L,
	log2(F, Log2),
	sigma(Ls, T, E1),
	E is (F * Log2) + E1.

% final part with Scaler in log2 is to normalise values with log base k 
% https://stats.stackexchange.com/questions/95261/why-am-i-getting-information-entropy-greater-than-1
entropy(Deltalist, Entropy) :-
	list_to_set(Deltalist, Deltaset),
	sigma(Deltalist, Deltaset, Sigma),
	length(Deltaset, S),

	(	S = 1,
		Entropy is 0
	;	S > 1,
		log2(S, Scaler),
		Entropy is -(Sigma/Scaler)
	).

% Was experimenting with finding the best value for this but don't have enough power/time with computer to test this 
entropycutoff(Totalpackets, O) :-
	Totalpackets =< 10,
	O is 0.9 * (Totalpackets-1) * 0.1;
	O is 0.95.

% search function to identify C2 traffic. Call as follows, 100 refers to how many consequitive packets to search for.
% Call: search(T, S, D, 100, []).
search(T1, Src1, Dst1, Count1, Deltas1) :-
	(	Count1 > 0,
		netlog(T1, Src1, Dst1),
		netlog(T2, Src2, Dst2),
		Src1 = Src2,
		Dst1 = Dst2,
		T1 < T2,
		Count2 is Count1 - 1,
		Delta is T2 - T1,
		append(Deltas1, [Delta], Deltas2),
		length(Deltas2, Totalpackets),

		% Entropy check, - 2 here just in case the first two packets happen to be the same packet delta. Even if it fails, the next packet will unlikely match this, etc. So eventually if there is a c2 channel it will be detected. Might need to change 0.8 though, this value isn't optimised. Although i think 0.8 is good
		entropy(Deltas2, Entropy),
		entropycutoff(Totalpackets, Cutoff),
		Entropy >= Cutoff, % 0.9 - ((10 / (10 + Totalpackets - 2)) * 0.9)
	
		search(T2, Src2, Dst2, Count2, Deltas2)
	);	Count1 = 0.
