<!-- Copy and paste the converted output. -->


<p style="color: red; font-weight: bold">>>>>>  gd2md-html alert:  ERRORs: 0; WARNINGs: 0; ALERTS: 9.</p>
<ul style="color: red; font-weight: bold"><li>See top comment block for details on ERRORs and WARNINGs. <li>In the converted Markdown or HTML, search for inline alerts that start with >>>>>  gd2md-html alert:  for specific instances that need correction.</ul>

<p style="color: red; font-weight: bold">Links to alert messages:</p><a href="#gdcalert1">alert1</a>
<a href="#gdcalert2">alert2</a>
<a href="#gdcalert3">alert3</a>
<a href="#gdcalert4">alert4</a>
<a href="#gdcalert5">alert5</a>
<a href="#gdcalert6">alert6</a>
<a href="#gdcalert7">alert7</a>
<a href="#gdcalert8">alert8</a>
<a href="#gdcalert9">alert9</a>

<p style="color: red; font-weight: bold">>>>>> PLEASE check and correct alert issues and delete this message and the inline alerts.<hr></p>



# Attestestation Test App

Table of Contents


[TOC]



## Description

Attestprops is a test app that calls the Attestation API’s.

The app works on a Android or Android TV device.



<p id="gdcalert1" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image1.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert2">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image1.png "image_tooltip")


Mobile Screenshot			Screenshot from Android TV Device

The app also contains instrumented tests which will allow Attestestation testing to be integrated into workflows, such as Continues Build process or Factory production line testing.

When built there are 2 apk’s produced, the apk for the app which shows the UI above and the apk which contains the test runner that runs the tests by launching the app apk and performing instrumented tests on a device or emulator.


### Running Tests and Viewing Test Summary

The tests  can be run a number of different ways, either from Android Studio, from adb, or using the gradlew command.

If you use Android Studio or gradlew from the command line, you will need to download the source.  However, if you do, you will also get a Test Summary report.

Below is an example of a Test Summary Report.  More details on how to access this report can be found later in the document.



<p id="gdcalert2" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image2.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert3">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image2.png "image_tooltip")



### How to Download the apk’s

The apk’s can be found [here](https://drive.google.com/drive/folders/1k1yGCS80QH7SRbFgGVFzgT-dhiH-g9G6?resourcekey=0-vqSjfSzRgwv9vDot_lL9Yw&usp=sharing)


### Downloading the Source

The source can be found here [https://github.com/jalong4/AttestProps](https://github.com/jalong4/AttestProps)


## Change Log


### Dec 5 changes

Added Instrumented tests


#### Run all tests:

Install both the app and test apks using `adb install &lt;apk name>` and then run the tests using the commands below:

adb shell am instrument -w -e class com.google.jimlongja.attestprops.AttestPropsTest \

com.google.jimlongja.attestprops.test/androidx.test.runner.AndroidJUnitRunner


#### To run a specific test:

adb shell am instrument -w -e class \

com.google.jimlongja.attestprops.AttestPropsTest#VerifiedBootIsSupported  \

com.google.jimlongja.attestprops.test/androidx.test.runner.AndroidJUnitRunner


#### Download the source

You can download the source from [here](https://github.com/jalong4/AttestProps), download the zip file and unzip it to a folder.

If you download the source you can run the tests from android studio by:


#### Run tests from Android Studio

Open source folder in Android Studio and run the tests.  This will install both the app and test apks and run the tests.


#### Run Tests from Command Line

Run from command line from the root folder of the source code:


```
./gradlew connectedAndroidTest
```


Or use the abbreviation


```
./gradlew cAT
```


Or run a specific test via gradlew


```
./gradlew connectedAndroidTest \
-Pandroid.testInstrumentationRunnerArguments.class= \
com.google.jimlongja.attestprops.AttestPropsTest#VerifiedBootIsSupported 
```


Command to filter output to just test status or Failed or Skipped


```
./gradlew connectedAndroidTest --info \
-Pandroid.testInstrumentationRunnerArguments.class=com.google.jimlongja.attestprops.AttestPropsTest 2>&1 | \
grep "com.google.jimlongja.attestprops.AttestPropsTest > \|Total tests"
```


Sample Output:



<p id="gdcalert3" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image3.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert4">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image3.png "image_tooltip")




On Sabrina with Android Q



<p id="gdcalert4" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image4.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert5">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image4.png "image_tooltip")


Note:  My Sabrina is an EVT.  The Sabrina sold in store will passVerifiedBootStateIsVerified

On Pixel 3 with Android Q



<p id="gdcalert5" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image5.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert6">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image5.png "image_tooltip")


Pixel 3 does not fail any tests.  Skipped tests in this case means that the test doesn’t apply until Android S (SDK level 31 and higher).

Here is the associated test summary:



<p id="gdcalert6" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image6.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert7">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image6.png "image_tooltip")


Note that skipped tests show as “passed” on the html summary.

If you don’t filter the output, it’s a bit confusing as the output will look like the command fails if any of the tests fail (which they mostly will until we get all the features supported in Android S). See screenshot below:



<p id="gdcalert7" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image7.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert8">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image7.png "image_tooltip")



##### View Test Summary

After running the gradle command, you can open an html summary file by typing the following command from your terminal prompt:


```
open -a "Google Chrome" app/build/reports/androidTests/connected/flavors/debugAndroidTest/index.html
```


This will give a test summary web page.  See screenshot below:



<p id="gdcalert8" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image8.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert9">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image8.png "image_tooltip")


Here is a different view using my Pixel 3 phone as the device under test:



<p id="gdcalert9" ><span style="color: red; font-weight: bold">>>>>>  gd2md-html alert: inline image link here (to images/image9.png). Store image on your image server and adjust path/filename/extension if necessary. </span><br>(<a href="#">Back to top</a>)(<a href="#gdcalert10">Next alert</a>)<br><span style="color: red; font-weight: bold">>>>>> </span></p>


![alt_text](images/image9.png "image_tooltip")


