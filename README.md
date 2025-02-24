# GGXrdFasterLoadingTimes

## Description

For Guilty Gear Xrd Rev2 version 2211 (2211 - the number displayed on the main manu in the lower right corner after launching the game). Makes the pre-battle loading screen load game contents synchronously, instead of asynchronously, therefore speeding up the loading times significantly on faster machines with fast hard disk read speeds (like SSD). Works as of 24'th February 2025.

Works as a patcher. You only need to apply the patch once, and the game will work with the changes forever.

The patched game has been tested to work properly in single- and multi-player modes.

If the game is of a version that's different from 2211, the patcher may crash, or the game may start crashing after patching.

## How to use

If you're on Windows, launch the `GGXrdFasterLoadingTimes.exe` and select the GuiltyGearXrd.exe file, located in the game's Steam directory. For example, here: `C:\Program Files (x86)\Steam\steamapps\common\GUILTY GEAR Xrd -REVELATOR-\Binaries\Win32\GuiltyGearXrd.exe`

If you're on Linux, launch `./GGXrdFasterLoadingTimes_linux` and paste or type in the path to your GuiltyGearXrd.exe file into the terminal window. You might be able to find it in `/home/YOUR_USER/.steam/steamapps/common/GUILTY GEAR Xrd -REVELATOR-\Binaries\Win32\GuiltyGearXrd.exe`

Afterwards, in both cases, the patcher will create a backup copy of the .EXE file and attempt to patch it. If successful, a `Patch successful!` message will appear.

Patch only needs to be applied once in forever.

To undo the patch, simply replace GuiltyGearXrd.exe with the backup copy of it that was created prior to patching.

## Credits

Thanks to WorseThanYou (@worsety) for consulting and ideas on what to do!

## How it works

The loading in Xrd works asynchronously, meaning it performs loading on the main thread. Every frame, the main thread performs loading for a little bit, until it runs out of time allotted for doing so, and then, for the remainder of the frame, the main thread animates the loading screen. This repeats on the next frame, and so on, until loading finishes.

The reason this is slow is because the developers of Unreal Engine 3 have placed a 0.003 or 0.005 (hard to tell) seconds limit on the amount of time the game is allowed to perform loading each frame. This is very, very little, and on modern computers the main thread ends up doing mostly nothing every frame.

Our patch increases that limit to infinity, so now the main thread can spend as much time as it needs per frame to do the loading. As a result, the loading screen animations suffer. But who cares, since it's loading so fast now, right?

### But it has a graphics rendering thread, why does it not use it?

It does. But it consumes vertices data that were prepared by the main thread, so the main thread still has to prepare those.

### Why is loading not performed on a different thread, in the background?

Unreal Engine 3 is a very old engine. In the past, most CPUs were single-core, hence only one thread. Also, performing loading on the same thread that runs most other things simplifies your code greatly and means you don't have to worry about data synchronization.

### If most CPUs were single-core, then why does it have a separate graphics thread?

Interacting with the graphics card was (and probably still is) believed to be slow and cause stalling in code execution. If only the graphics thread interacts with the graphics card, then we don't care about that as much, because while the graphics thread is stalled, the main thread can still work and perform tasks on the CPU.

### Why is the patcher code so giant, do you not need to replace just two bytes?

There was a problem where you could mash to skip the loading screen before it has finished loading, which lead to a crash. If you mashed after it has finished loading, then it wouldn't crash. A fix was needed to exclude the possibility of a crash, and so the patcher takes care of that as well.
