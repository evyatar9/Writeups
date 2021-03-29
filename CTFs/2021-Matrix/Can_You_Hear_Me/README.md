# Can_You_Hear_Me - Matrix Cyber Labs CTF 2021
Forensic, 50 Points

## Description

*I think I heard something. I'm pretty sure it was around 3:00 pm...*

And attached file [Can_You_Hear_Me](Can_You_Hear_Me)

## Can_You_Hear_Me Solution

First, Let's check the file type:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Can_You_Hear_Me]
└──╼ $file Can_You_Hear_Me 
Can_You_Hear_Me: data
```

```strings``` command also not produce something meaningful.

Let's try to use ```xxd``` to find the pattern in bytes as follow:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Can_You_Hear_Me]
└──╼ $cat Can_You_Hear_Me | xxd -g 1 -c 20 | less
00000000: f3 ff c4 44 00 00 03 00 00 48 00 00 17 00 91 05 03 f6 04 b8  ...D.....H..........
00000014: 63 60 32 13 87 e6 8a a1 48 06 7e 99 5e fd 43 af c5 10 b1 62  c`2.....H.~.^.C....b
00000028: ca e3 20 6b 00 00 83 00 82 8b 2e 0e 2e 1f 70 fe 3e b8 13 7c  .. k..........p.>..|
0000003c: de 07 fe 53 40 90 0c 10 81 44 ff 8f ff ff a3 fc 00 b1 0f 3e  ...S@....D.........>
00000050: 0a c1 f0 c1 0e fa 61 05 70 a0 b3 22 65 8c 4e 5f f3 ff c4 44  ......a.p.."e.N_...D
00000064: 11 53 79 e8 01 f0 10 4f 63 00 e7 a5 32 a3 d3 c9 4e 82 0e 73  .Sy....Oc...2...N..s
00000078: 9a c5 cb b8 63 f4 aa 08 f8 61 9b 16 2f 1d 81 9c 8f 73 cb 02  ....c....a../....s..
0000008c: 90 ad 34 45 15 10 58 a8 59 58 84 58 de 68 a4 c9 a0 93 ac 1a  ..4E..X.YX.X.h......
000000a0: 3a 93 eb 41 7a a5 a2 97 a2 a2 5c 6c db 64 1b 74 b6 5a 17 9a  :..Az.....\l.d.t.Z..
000000b4: ce cd bd 9b df 75 d0 6b 56 65 98 8c f3 ff c4 44 21 5e 2a 23  .....u.kVe.....D!^*#
000000c8: 01 2c 98 9d 34 00 66 22 4c f4 6d d3 e9 5f ad 55 d5 f6 d0 41  .,..4.f"L.m.._.U...A
000000dc: a6 42 90 5a f5 43 ae 6a a9 fb ad 99 75 7d 99 ed 46 ba cd 74  .B.Z.C.j....u}..F..t
000000f0: 2f d0 7a 9f 04 12 38 cd 04 12 01 62 6b a0 81 b1 99 01 f1 8a  /.z...8....bk.......
00000104: 89 89 31 61 c2 8b 87 81 71 42 02 9e 30 08 34 a9 0d cc 14 01  ..1a....qB..0.4.....
00000118: 60 00 c1 28 00 51 80 c1 f3 ff c4 44 1c 2c a2 99 01 60 98 9d  `..(.Q.....D.,...`..
0000012c: 20 00 1d 44 13 04 64 20 0a 40 8f 30 33 01 90 14 82 b2 10 c0   ..D..d .@.03.......
00000140: f8 41 0a 63 27 6b 89 88 5a 16 1c 04 69 cd a0 1b 24 bb 5b 5e  .A.c'k..Z...i...$.[^
00000154: 28 cd 77 21 ff fa 7a fa 6c fa 6a a5 7d ad a6 e8 d3 9a e9 7c  (.w!..z.l.j.}......|
00000168: 90 e0 ab b8 7f 3b ff ff b3 ff 55 f2 cf 65 4e 32 30 98 89 39  .....;....U..eN20..9
0000017c: 9f 13 e0 07 f3 ff c4 44 13 0c 96 f8 01 70 30 db d1 00 83 79  .......D.....p0....y
00000190: 85 80 82 85 0c 0d 7c ee ca d4 89 05 1c 50 1c 24 82 62 76 0a  ......|......P.$.bv.
000001a4: 63 b8 28 4d 26 aa a1 62 ac a8 af 9a a5 3c 4f d7 78 a0 0f 82  c.(M&..b.....<O.x...
000001b8: 70 aa cb fd 1d 50 ff d3 01 fd c3 00 e1 ee 20 63 ff f9 ff ff  p....P........ c....
000001cc: ff ff 4a ff df 96 69 e3 21 d0 1a 73 b1 1f 7d 2a 45 85 75 8e  ..J...i.!..s..}*E.u.
000001e0: f3 ff c4 44 15 0f 92 a9 00 98 44 de 9c 94 6e 04 4e f3 20 30  ...D......D...n.N. 0
000001f4: 80 69 0b 25 f1 f7 c8 d7 30 c3 21 e4 d9 60 b2 bc e9 5a 43 24  .i.%....0.!..`...ZC$
00000208: d3 ea c4 fe 47 4e 87 4f 3c ef f5 ff 1b 96 e7 7c ff ff 46 a6  ....GN.O<......|..F.
0000021c: 09 40 74 0e 59 66 b7 08 08 21 0e a9 04 71 e3 d9 8a 40 ff 77  .@t.Yf...!...q...@.w
00000230: ff ff 91 fe ef 3d eb 3f 11 37 eb 6d 4a b8 9b c1 f3 ff c4 44  .....=.?.7.mJ......D
00000244: 13 0b a2 d9 00 b4 06 c6 59 94 f3 d6 32 dd 82 08 db 56 ba e5  ........Y...2....V..
00000258: 7c 89 03 0e 76 db 10 fe f1 58 89 20 34 fc 27 fa 34 23 f1 cf  |...v....X. 4.'.4#..
0000026c: 2b a9 ff b7 01 be f0 bf e5 ff b2 3f 18 bf 97 18 9c 80 30 60  +..........?......0`
00000280: 86 37 76 4e 34 94 61 cd d2 3b 1a 61 a2 bd c2 c2 6a 72 38 eb  .7vN4.a..;.a....jr8.
00000294: c3 2f 2f 23 5a 48 a0 42 0c d9 88 f3 f3 ff c4 44 13 0e 4e 59  .//#ZH.B.......D..NY
000002a8: 00 bc 0a 8e 03 95 19 06 3d 79 d4 ed 81 71 75 d4 bd 35 99 44  ........=y...qu..5.D
000002bc: 0f cc a9 86 53 a8 a7 15 ff db 55 ca 9f 77 0b f2 2a f5 63 36  ....S.....U..w..*.c6
...
```

We can see sort of a pattern ```f3 ff c4 44```.

Let's try to align the hex dump so every line will be prefixed with ```f3 ff c4 44```:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Can_You_Hear_Me]
└──╼ $cat Can_You_Hear_Me | xxd -g 1 -c 192 | less
00000000: f3 ff c4 44 00 00 03 00 00 48 00 00 17 00 91 05 03 f6 04 b8 63 60 32 13 87 e6 8a a1 48 06 7e 99 5e fd 43 af c5 10 b1 62 ca e3 20 6b 00 00 83 00 82 8b 2e 0e 2e 1f 70 fe 3e b8 13 7c 
de 07 fe 53 40 90 0c 10 81 44 ff 8f ff ff a3 fc 00 b1 0f 3e 0a c1 f0 c1 0e fa 61 05 70 a0 b3 22 65 8c 4e 5f f3 ff c4 44 11 53 79 e8 01 f0 10 4f 63 00 e7 a5 32 a3 d3 c9 4e 82 0e 73 9a c5 cb b
8 63 f4 aa 08 f8 61 9b 16 2f 1d 81 9c 8f 73 cb 02 90 ad 34 45 15 10 58 a8 59 58 84 58 de 68 a4 c9 a0 93 ac 1a 3a 93 eb 41 7a a5 a2 97 a2 a2 5c 6c db 64 1b 74 b6 5a 17 9a ce cd bd 9b df 75 d0
 6b 56 65 98 8c  ...D.....H..........c`2.....H.~.^.C....b.. k..........p.>..|...S@....D.........>......a.p.."e.N_...D.Sy....Oc...2...N..s....c....a../....s....4E..X.YX.X.h......:..Az.....\l.
d.t.Z.......u.kVe..
000000c0: f3 ff c4 44 21 5e 2a 23 01 2c 98 9d 34 00 66 22 4c f4 6d d3 e9 5f ad 55 d5 f6 d0 41 a6 42 90 5a f5 43 ae 6a a9 fb ad 99 75 7d 99 ed 46 ba cd 74 2f d0 7a 9f 04 12 38 cd 04 12 01 62 
6b a0 81 b1 99 01 f1 8a 89 89 31 61 c2 8b 87 81 71 42 02 9e 30 08 34 a9 0d cc 14 01 60 00 c1 28 00 51 80 c1 f3 ff c4 44 1c 2c a2 99 01 60 98 9d 20 00 1d 44 13 04 64 20 0a 40 8f 30 33 01 90 1
4 82 b2 10 c0 f8 41 0a 63 27 6b 89 88 5a 16 1c 04 69 cd a0 1b 24 bb 5b 5e 28 cd 77 21 ff fa 7a fa 6c fa 6a a5 7d ad a6 e8 d3 9a e9 7c 90 e0 ab b8 7f 3b ff ff b3 ff 55 f2 cf 65 4e 32 30 98 89
 39 9f 13 e0 07  ...D!^*#.,..4.f"L.m.._.U...A.B.Z.C.j....u}..F..t/.z...8....bk.........1a....qB..0.4.....`..(.Q.....D.,...`.. ..D..d .@.03........A.c'k..Z...i...$.[^(.w!..z.l.j.}......|.....
;....U..eN20..9....
00000180: f3 ff c4 44 13 0c 96 f8 01 70 30 db d1 00 83 79 85 80 82 85 0c 0d 7c ee ca d4 89 05 1c 50 1c 24 82 62 76 0a 63 b8 28 4d 26 aa a1 62 ac a8 af 9a a5 3c 4f d7 78 a0 0f 82 70 aa cb fd 
1d 50 ff d3 01 fd c3 00 e1 ee 20 63 ff f9 ff ff ff ff 4a ff df 96 69 e3 21 d0 1a 73 b1 1f 7d 2a 45 85 75 8e f3 ff c4 44 15 0f 92 a9 00 98 44 de 9c 94 6e 04 4e f3 20 30 80 69 0b 25 f1 f7 c8 d
7 30 c3 21 e4 d9 60 b2 bc e9 5a 43 24 d3 ea c4 fe 47 4e 87 4f 3c ef f5 ff 1b 96 e7 7c ff ff 46 a6 09 40 74 0e 59 66 b7 08 08 21 0e a9 04 71 e3 d9 8a 40 ff 77 ff ff 91 fe ef 3d eb 3f 11 37 eb
 6d 4a b8 9b c1  ...D.....p0....y......|......P.$.bv.c.(M&..b.....<O.x...p....P........ c......J...i.!..s..}*E.u....D......D...n.N. 0.i.%....0.!..`...ZC$....GN.O<......|..F..@t.Yf...!...q...
@.w.....=.?.7.mJ...
00000240: f3 ff c4 44 13 0b a2 d9 00 b4 06 c6 59 94 f3 d6 32 dd 82 08 db 56 ba e5 7c 89 03 0e 76 db 10 fe f1 58 89 20 34 fc 27 fa 34 23 f1 cf 2b a9 ff b7 01 be f0 bf e5 ff b2 3f 18 bf 97 18 
9c 80 30 60 86 37 76 4e 34 94 61 cd d2 3b 1a 61 a2 bd c2 c2 6a 72 38 eb c3 2f 2f 23 5a 48 a0 42 0c d9 88 f3 f3 ff c4 44 13 0e 4e 59 00 bc 0a 8e 03 95 19 06 3d 79 d4 ed 81 71 75 d4 bd 35 99 4
4 0f cc a9 86 53 a8 a7 15 ff db 55 ca 9f 77 0b f2 2a f5 63 36 fa 39 b3 19 0b 09 7b 14 a4 9c 03 0c cc 87 70 54 1d 28 95 10 12 62 6b cf fb ff 0b ff ff 55 da fe d5 05 7b ba 45 e0 3e 81 1b ef b3
 b4 03 62 e5 49  ...D........Y...2....V..|...v....X. 4.'.4#..+..........?......0`.7vN4.a..;.a....jr8..//#ZH.B.......D..NY........=y...qu..5.D....S.....U..w..*.c6.9....{.......pT.(...bk......
U....{.E.>......b.I
00000300: f3 ff c4 44 11 13 5e d9 00 c0 0a 7e 9c 94 c3 ce 55 22 f2 56 6e ff 93 44 bc 49 f7 b1 ab 29 ac 45 ff 73 b5 2a e5 30 e8 67 a7 ff e5 d3 35 41 88 42 06 94 1f 1c 49 8b 87 02 0a 0b ff 8d 
ff ff ff ff 6a a5 90 f9 81 67 64 db e4 0c 20 f0 48 a2 6c a8 07 8b 07 44 08 68 c5 90 52 4c d8 0f 04 2d ee 4f f3 ff c4 44 11 1e 6e 29 00 bc 84 94 82 94 06 67 7d 58 45 bf 57 13 5f f9 ff ec ff 7
f 4c f9 0c 71 14 c6 71 18 83 e7 88 ae 87 84 83 14 7a f6 ff 3f ff ff 45 d9 ef ff 04 f7 07 11 6b 7f f6 3a 05 af 3a da 27 c9 4d 8d 4a 94 ad 86 54 03 51 2c 3e 91 33 53 34 58 36 00 f2 18 13 27 1e
 2a 92 6e fd 49  ...D..^....~....U".Vn..D.I...).E.s.*.0.g....5A.B....I...........j....gd... .H.l....D.h..RL...-.O...D..n).......g}XE.W._.....L..q..q.........z..?..E.......k..:..:.'.M.J...T.Q
,>.3S4X6....'.*.n.I
000003c0: f3 ff c4 44 11 2c 7a f9 00 ac 0a cd 1f 94 7f e6 ff a7 d5 ef 61 00 5c 72 1d aa 7c 15 fa 38 40 49 a1 a1 ff db ff ff e8 ff b1 d2 3f cc 45 09 c2 29 b2 14 5b 9e 28 31 10 1c 50 f3 1b fb 
17 99 26 c3 dd 03 59 85 87 7c b1 8a 1c 8c 4c 03 99 68 9b a0 c3 31 d5 1f ff ff ff ff 58 ff 09 a5 20 0d ee 61 f3 ff c4 44 11 37 66 59 00 a4 c4 cc 42 94 b2 9e 8c 63 fa a1 ff 11 ff ff 5e fc 55 6
5 de 8f f6 a7 30 c8 30 53 81 cc 55 44 24 52 9a 96 a1 2d 31 7a 30 61 e4 f8 09 3b 8f 29 05 ae 0b 4a 29 49 da 09 3a 15 8f 76 ff d5 a8 f5 8e f2 f5 a3 86 06 41 03 48 d8 0e 1a af e1 ff ff b8 fa 54
 2c 06 62 06 36  ...D.,z.............a.\r..|..8@I..........?.E..)..[.(1..P.....&...Y..|....L..h...1......X... ..a...D.7fY....B....c......^.Ue....0.0S..UD$R...-1z0a...;.)...J)I..:..v.........
.A.H.........T,.b.6
00000480: f3 ff c4 44 10 44 82 28 00 88 d8 c3 a5 48 98 7c 8a c3 0f b0 10 78 02 82 05 52 4b 1e d8 5a 39 98 5c 78 9a d7 ad 96 52 76 63 ba fb d0 72 ab b7 d4 8a 23 12 0a e5 50 1e 1b e8 ec 15 14 
2a 62 ed 0a cc b5 53 25 52 e8 49 bd 5c 42 ba ff fb 9b 7e 76 7f af cb 9d 70 55 e7 dd 5a 92 00 20 20 92 1a 88 f3 ff c4 44 12 56 8e 88 01 34 30 59 01 00 49 a2 1a 33 86 75 06 3b ec 88 fc 25 31 0
d 2a 00 0d 64 5f 08 38 f0 c0 60 14 ca 88 13 8f 0b c0 ff 94 c1 70 03 0e 60 20 71 e2 30 3b c6 c6 ff a2 e0 8c 0b e3 59 5c b8 ff 1f 20 88 46 43 47 4c e0 e3 04 64 ff e1 8e ff 13 59 63 1a 48 90 91
 0d 66 ec e9 04  ...D.D.(.....H.|.....x...RK..Z9.\x....Rvc...r....#...P......*b....S%R.I.\B....~v....pU..Z..  ......D.V...40Y..I..3.u.;...%1.*..d_.8..`..........p..` q.0;........Y\... .FCGL.
..d.....Yc.H...f...

```
Still, we are not see any string that can make sense (b64 etc).

Now Let's try to look for known audio file magic header (I guess it's related to audio because of the challenge description "I think I heard something....")

According [(List_of_file_signatures)](https://en.wikipedia.org/wiki/List_of_file_signatures) we can see:
```
FF FB

FF F3

FF F2

0	mp3	MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)
```

```FF F3``` It's related to mp3 file format - our first bytes is - ```f3 ff``` It's look like they swapped, let's try to make swap for each two bytes.

Let's write a simple python program to make it:
```python
file = open('Can_You_Hear_Me','rb').read()

flip = [file[i^1] for i in range(len(file))]

with open('swap_Can_You_Hear_Me','wb') as f:
	f.write(bytearray(flip))
```

Run the script:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Can_You_Hear_Me]
└──╼ $python swapbytes.py 
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Can_You_Hear_Me]
└──╼ $file swap_Can_You_Hear_Me 
swap_Can_You_Hear_Me: MPEG ADTS, layer III, v2,  32 kbps, 24 kHz, Monaural

```
Now, Just listen to the swap_Can_You_Hear_Me and get the flag :)

