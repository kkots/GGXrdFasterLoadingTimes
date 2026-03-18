# GGXrdFasterLoadingTimes

## Description

Speed comparison (on my PC):
<https://youtu.be/dV8kicV9BhA>

For Guilty Gear Xrd Rev2 version 2211 (2211 - the number displayed on the main menu in the lower right corner after launching the game). Makes the pre-battle loading screen load game contents synchronously, instead of asynchronously, therefore speeding up the loading times significantly on faster machines with fast hard disk read speeds (like SSD). Works as of 14'th March 2026.

Also speeds up the initial loading of the game and has an option to skip (or to become able to press Enter to skip) the intro movie that shows ArcSys, Team RED, Unreal Engine and Autodesk logos.

Works as a patcher. You only need to apply the patch once, and the game will work with the changes forever.

The patched game has been tested to work properly in single- and multi-player modes.

If the game is of a version that's different from 2211, the patcher may crash, or the game may start crashing after patching.

## How to use

If you're on Windows, launch the `GGXrdFasterLoadingTimes.exe` and select the GuiltyGearXrd.exe file, located in the game's Steam directory. For example, here: `C:\Program Files (x86)\Steam\steamapps\common\GUILTY GEAR Xrd -REVELATOR-\Binaries\Win32\GuiltyGearXrd.exe`

If you're on Linux, launch `./GGXrdFasterLoadingTimes_linux`. If it doesn't launch, make sure you have the execute permission: `chmod u+x GGXrdFasterLoadingTimes_linux`. After it launches, paste or type in the path to your GuiltyGearXrd.exe file into the terminal window, or drag-n-drop the GuiltyGearXrd.exe file onto the terminal window. You might be able to find the EXE in `/home/YOUR_USER/.steam/root/steamapps/common/GUILTY GEAR Xrd -REVELATOR-/Binaries/Win32/GuiltyGearXrd.exe`

Afterwards, in both cases, the patcher will create a backup copy of the .EXE file and attempt to patch it. If successful, a `Patch successful!` message will appear.

Patch only needs to be applied once in forever.

To undo the patch, simply replace GuiltyGearXrd.exe with the backup copy of it that was created prior to patching.
To undo skipping of the intro movie, go to REDGame/Config/REDEngine.ini and remove the `SkippableMovies=Splash_Steam` line from it, if present, and in the REDGame/Movies folder find the `Splash_Steam_.wmv` file and rename it to `Splash_Steam.wmv`.

## Undoing the patch

See above.

## Credits

Thanks to WorseThanYou (@worsety) for consulting and ideas on what to do!

## How it works

**Regarding the pre-battle loading**, in Xrd it works asynchronously, meaning it performs loading on the main thread. Every frame, the main thread performs loading for a little bit, until it runs out of time allotted for doing so, and then, for the remainder of the frame, the main thread animates the loading screen. This repeats on the next frame, and so on, until loading finishes.

The reason this is slow is because the developers of Unreal Engine 3 have placed a 0.003 or 0.005 (hard to tell) seconds limit on the amount of time the game is allowed to perform loading each frame. This is very, very little, and on modern computers the main thread ends up doing mostly nothing every frame.

Our patch increases that limit to infinity, so now the main thread can spend as much time as it needs per frame to do the loading. As a result, the loading screen animations suffer. But who cares, since it's loading so fast now, right?

**Regarding the initial game startup**, developers at ArcSys have deliberately inserted pauses between the loading messages and on the loading messages themselves, so that each message can be read clearly. The "Verifying downloadable content." in particular does nothing and just waits for 60 frames. All we do is remove the wait times, and we could probably shorten the loading even more by removing the appearing and disappearing animations on each message and by doing something about the "Loading most recent information." (that one seems to be doing something through Steam API, and doesn't seem to have straight up empty waits).

**Regarding skipping of the intro movie**, the guide on Dustloop (<https://www.dustloop.com/w/GGXRD-R2/Resources#Skip_Intro_Movies>) says to change `bForceNoMovies=FALSE` to `bForceNoMovies=TRUE` in REDGame/Config/REDEngine.ini, and that works, but that causes the promo/demo movie to not play even when the game is idle on the title screen for enough time. Alternative solution, that the patcher uses, is to rename the REDGame/Movies/Splash_Steam.wmv file, which makes only it not play. On your own, you could delete the entire Movies folder to save hard disk space, as none of the movies are actually needed and the game runs fine without them, but the patcher won't delete that folder for you. Another solution that the patcher may use is to edit REDGame.ini and add a `SkippableMovies=Splash_Steam` line into the `[FullScreenMovie]` section. That makes it able so you can press Enter to skip the intro movie. In order to undo what the patcher has done, you must manually edit that line out and/or rename the Splash_Steam.wmv file to its original name \(Splash_Steam.wmv\).

### But it has a graphics rendering thread, why does it not use it?

It does. But it consumes vertices data that were prepared by the main thread, so the main thread still has to prepare those.

### Why is loading not performed on a different thread, in the background?

Unreal Engine 3 is a very old engine. In the past, most CPUs were single-core, hence only one thread. Also, performing loading on the same thread that runs most other things simplifies your code greatly and means you don't have to worry about data synchronization.

### If most CPUs were single-core, then why does it have a separate graphics thread?

Interacting with the graphics card was (and probably still is) believed to be slow and cause stalling in code execution. If only the graphics thread interacts with the graphics card, then we don't care about that as much, because while the graphics thread is stalled, the main thread can still work and perform tasks on the CPU.

### Why is the patcher code so giant, do you not need to replace just two bytes?

There was a problem where you could mash to skip the loading screen before it has finished loading, which lead to a crash. If you mashed after it has finished loading, then it wouldn't crash. A fix was needed to exclude the possibility of a crash, and so the patcher takes care of that as well. Additionally, as of Version 1.4 of this mod, there is an extra option to automatically mash on loading screens to skip them without manual input, and this took extra code to implement.

## Why does Windows Defender think this is a virus?

I don't know. All this does is patch the .EXE file you have yourself selected, after a manual confirmation. I gave up trying to research this after a freshly compiled Hello World from Visual Studio was flagged as a potentially unsafe download by Google Chrome. Nothing helps: adding a VERSIONINFO, signing the patcher with a self-signed certificate, putting all of Shakespeare works into it - nothing.

The best you can do is add this to exceptions. If you're still worried this might be a virus: read through and compile this project yourself, the code is open. You might need a Visual Studio on Windows, as this project was created in that environment. On Linux the project is compiled using CMake. See CMakeLists.txt for details (Linux only, not used for Visual Studio).

## Changelog

- 2025 March 3: Fixed a crash when mashing through the loading screen in offline versus human vs human. To apply the patch again you need to find an unpatched backup copy of GuiltyGearXrd.exe and apply the new patcher to it.
- 2025 March 4: Version 1.2: Signed the executable, so that it is less likely that it gets flagged by Windows Defender as a virus.
- 2025 March 8: Version 1.3: Changed the type of the app from console to window, so that it gets flagged less often as a virus by Windows Defender. Linux version of the patcher unchanged.
- 2025 July 25: Version 1.4: Added an option to automatically mash through the loading screens once they've finished loading.
- 2026 March 14: Version 1.5: Added more patching that speeds up the game's loading on startup.
- 2026 March 18: Version 1.6: Added another change that the patcher can make. Now it asks if the user wants to see the ArcSys, Team RED, Unreal Engine, Autodesk logos at the start of the game. If not, it asks if the user wants to hide that intro entirely, or wants to be able to press Enter to skip it. If the user chooses to hide the into entirely, the `GUILTY GEAR Xrd -REVELATOR-\REDGame\Movies\Splash_Steam.wmv` file gets renamed. If the user chooses to become able to press Enter to skip the intro, the `[FullScreenMovie]` section of `GUILTY GEAR Xrd -REVELATOR-\REDGame\Config\REDEngine.ini` gets a new entry: `SkippableMovies=Splash_Steam`. If the user responds that they want to see the logos, nothing gets changed. If any changes to the REDEngine.ini are made by the patcher, the GuiltyGearXrd.exe is also patched to prevent the RED\* INI files from being overwritten due to daylight saving, and all RED\* files get their IniVersion timestamps updated. The latter patch is available stand-alone in another repo: <https://github.com/kkots/GGXrdStopResettingINITwiceAYear>
