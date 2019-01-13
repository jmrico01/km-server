// ----------------------------------------------------------------------------
//
// Jose M Rico
// logo.js
// Landing Page Animation, www.kapricornmedia.com
// Copyright Kapricorn Media, 2016
//
// ----------------------------------------------------------------------------


// --------------------------- KNOWN ANIMATION DATA ---------------------------
// Path to image files
var IMG_PATH 		= "images/logo/";
// Frames to milliseconds conversion for timing information
var FRAME_TO_MS 	= 1/(29.997) * 1000;
// Total number of frame image files
var NUM_FRAME_FILES = 47;
// Total number of still frames (number of transitions + 1)
var NUM_STILLS 		= 9;
// Frame image file dimensions
var FRAME_WIDTH 	= 400;
var FRAME_HEIGHT	= 450;

// Indices of still frames that precede each animation
var FRAME_IND_STILL	= [0, 11, 15, 16, 24, 29, 35, 42, 46];
// Indices of animation frames, grouped into arrays
// according to which still frame they follow
var FRAME_IND_ANIM  = [
	[1,  0,  1,  2,  3,  1,  4,  5,  4,  2,  6,  7,  8,  9,  8,  7,  9,  7,  9,  7,  6, 10, 11, 12, 10,  9, 11, 12],
	[10, 11, 6,  12, 6,  12, 13, 14, 15, 13, 15, 14],
	[14, 13, 14, 20, 18, 17],
	[17, 18, 17, 19, 20, 21, 22, 23, 24, 23, 22, 25, 22, 23],
	[22, 25, 26, 27, 28, 29, 26, 27, 30, 26, 27],
	[27, 29, 28, 29, 31, 32, 31, 32, 33, 34, 35, 34, 33, 34],
	[34, 33, 36, 37, 38, 39, 40, 41, 40, 42, 41, 40, 41],
	[41, 40, 39, 38, 40, 43, 44, 45],
	[45, 44, 43,  2,  3,  1]];

// Minimum display time for still frames (in milliseconds)
var FRAME_TIME_STILL = 4000;
// Display time for animated frames, following the sequence
// of frameIndAnim (in frame number)
var FRAME_TIME_ANIM	= [
	[4,  4,  1,  1,  2,  1,  2,  2,  3,  1,  1,  1,  1,  2,  1,  1,  2,  1,  1,  1,  1,  1,  6,  2,  3,  2,  2,  1],
	[3,  1,  3,  2,  1,  2,  2,  2,  1,  2,  1,  2],
	[4,  2,  2,  2,  2,  2],
	[2,  2,  2,  2,  2,  2,  2,  2,  4,  1,  3,  3,  1,  2],
	[1,  1,  2,  2,  2,  14, 2,  2,  18, 2,  2],
	[1,  9,  1,  1,  1,  2,  1,  2,  3,  3,  60, 1,  1,  1],
	[1,  1,  2,  1,  1,  1,  2,  3,  2,  21, 1,  2,  2],
	[1,  1,  1,  1,  1,  2,  2,  2],
	[1,  1,  1,  1,  2,  1]];

// Film grain intensity multiplier for each FRAME IMAGE FILE
var FRAME_GRAIN_ALPHA = [
	1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
	0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 0, 0, 1, 0, 0, 1, 1,
	1, 1, 1, 1, 1, 1, 1];

// -------------------------- DYNAMIC ANIMATION DATA --------------------------
// Timing information
var time_start			= 0;
var time_elapsed 		= 0;

// Has the animation been initialized?
var initialized 		= false;
// Is the animation active?
var active 				= false;
// Is there a transition in progress?
var transition 			= false;

// Index of current still frame (from 0 to NUM_STILLS - 1)
var still_current		= 0;
// Index of current animation frame
// (from 0 to FRAME_IND_ANIM[still_current].length - 1)
var anim_frame_current	= 0;

// FRAME LOADER
var loader_frames 		= [];
var loader_anim_ready	= [];
var loader_still;
var loader_anim_frame;

// ------------------------- FILM GRAIN PATTERN DATA --------------------------
// Known parameters
var PATTERN_WIDTH 	= 80;
var PATTERN_HEIGHT 	= 80;
var PATTERN_ALPHA 	= 30;
var PATTERN_PIXELS	= PATTERN_WIDTH * PATTERN_HEIGHT * 4;

// Canvas
var pattern_canvas;
var pattern_ctx;
var pattern_data;

// ---------------------------- FUNCTIONS & OTHER -----------------------------
// Main logo canvas
var logo_ctx;
var logo_current_img;

// Makes Resize() be called on window load and Resize
window.onload		= Resize;
window.onresize 	= Resize;

// Entry point for window onload and resize events
function Resize()
{
	active = false;
	if (window.innerWidth > 700)
	{
		active = true;
		Start();
	}
}

// This function is called when the page loads or resizes
function Start()
{
	// Initialize canvas
	logo_ctx = document.getElementById('logoCanvas').getContext("2d");
	logo_ctx.globalCompositeOperation = "destination-atop";

	if (!initialized)
	{
		initialized = true;

		InitLoader();

		// Convert FRAME_TIME_ANIM from frames to milliseconds
		for (var i = 0; i < FRAME_TIME_ANIM.length; i++)
			for (var j = 0; j < FRAME_TIME_ANIM[i].length; j++)
				FRAME_TIME_ANIM[i][j] *= FRAME_TO_MS;

		// Randomize first still frame
		still_current = Math.floor(Math.random() * NUM_STILLS);

		// Force load first image
		var frame_ind = FRAME_IND_STILL[still_current];
		loader_frames[frame_ind] = new Image(FRAME_WIDTH, FRAME_HEIGHT);
        loader_frames[frame_ind].src = IMG_PATH + "animation"
            + frame_ind + ".png";
		loader_frames[frame_ind].onload = function() {
			logo_current_img = loader_frames[frame_ind];
			InitGrain();
			time_start = window.performance.now();
			requestAnimationFrame(Loop);
			loader_still = still_current;
			loader_anim_frame = anim_frame_current;
			LoaderNext();
		}
	}
	else
	{
		time_start = window.performance.now();
		requestAnimationFrame(Loop);
	}
}

function InitLoader()
{
	// Initialize all frames to unloaded
	for (var i = 0; i < NUM_FRAME_FILES; i++)
		loader_frames[i] = 0;

	// Initialize all transition animations to false (not ready)
	for (var i = 0; i < NUM_STILLS; i++)
		loader_anim_ready[i] = false;
}

function LoaderComplete()
{
	for (var i = 0; i < NUM_FRAME_FILES; i++)
		if (loader_frames[i] == 0)
			return false;

	return true;
}

function LoaderNext()
{
	if (loader_anim_frame >= FRAME_IND_ANIM[loader_still].length)
	{
		// Transition animation completely loaded
		var frame_ind = FRAME_IND_STILL[(loader_still + 1) % NUM_STILLS];
		if (loader_frames[frame_ind] == 0)
		{
			// Next still frame not loaded
			loader_frames[frame_ind] = new Image(FRAME_WIDTH, FRAME_HEIGHT);
			loader_frames[frame_ind].src = IMG_PATH+"animation"+frame_ind+".png";
			loader_frames[frame_ind].onload = LoaderNext;
		}
		else
		{
			// Next still frame loaded
			loader_anim_ready[loader_still] = true;
			loader_anim_frame = 0;
			loader_still = (loader_still + 1) % NUM_STILLS;

			// If all frames have been loaded, exit
			if (LoaderComplete())
			{
				for (var i = 0; i < NUM_STILLS; i++)
					loader_anim_ready[i] = true;

				return;
			}
			else
			{
				LoaderNext();
			}
		}
	}
	else
	{
		// Transition animation not checked completely
		var frame_ind = FRAME_IND_ANIM[loader_still][loader_anim_frame];
		loader_anim_frame++;
		if (loader_frames[frame_ind] == 0)
		{
			// This frame hasn't been loaded
			loader_frames[frame_ind] = new Image(FRAME_WIDTH, FRAME_HEIGHT);
			loader_frames[frame_ind].src = IMG_PATH+"animation"+frame_ind+".png";
			loader_frames[frame_ind].onload = LoaderNext;
		}
		else
		{
			// This frame was already loaded
			LoaderNext();
		}
	}
}

// Create film grain pattern canvas
function InitGrain()
{
    pattern_canvas = document.createElement("canvas");
    pattern_canvas.width = PATTERN_WIDTH;
    pattern_canvas.height = PATTERN_HEIGHT;
    pattern_ctx = pattern_canvas.getContext("2d");
    pattern_data = pattern_ctx.createImageData(PATTERN_WIDTH, PATTERN_WIDTH);
}

// Generate noise in the pattern canvas
function GenNoise()
{
    var value;
    for (var i = 0; i < PATTERN_PIXELS; i += 4)
    {
        value = (Math.random() * 255);
        pattern_data.data[i]   = value;
        pattern_data.data[i+1] = value;
        pattern_data.data[i+2] = value;
        pattern_data.data[i+3] = PATTERN_ALPHA;

        var frame_ind;
        if (transition)
        	frame_ind = FRAME_IND_ANIM[still_current][anim_frame_current];
        else
        	frame_ind = FRAME_IND_STILL[still_current];
		pattern_data.data[i+3] *= FRAME_GRAIN_ALPHA[frame_ind];
    }
    pattern_ctx.putImageData(pattern_data, 0, 0);
}

// Draw the film grain, and then the logo on top with "destination-atop" blending
// (the blending mode was set in the start() function)
function Draw()
{
    logo_ctx.clearRect(0, 0, FRAME_WIDTH, FRAME_HEIGHT);
    logo_ctx.fillStyle = logo_ctx.createPattern(pattern_canvas, 'repeat');
    logo_ctx.fillRect(0, 0, FRAME_WIDTH, FRAME_HEIGHT);
	logo_ctx.drawImage(logo_current_img, 0, 0);
}

// Main animation loop
function Loop()
{
	if (!active)
		return;

	time_elapsed = window.performance.now() - time_start;

	// Handle animation
	if (transition)
	{
		if (time_elapsed > FRAME_TIME_ANIM[still_current][anim_frame_current])
		{
			anim_frame_current++;
			time_start = window.performance.now();
			if (anim_frame_current >= FRAME_IND_ANIM[still_current].length)
			{
				transition = false;
				still_current = (still_current + 1) % NUM_STILLS;
				logo_current_img = loader_frames[FRAME_IND_STILL[still_current]];
			}
			else
			{
				logo_current_img = loader_frames[FRAME_IND_ANIM[still_current][anim_frame_current]];
			}
		}
	}
	else
	{
		if (time_elapsed > FRAME_TIME_STILL && loader_anim_ready[still_current])
		{
			transition = true;
			anim_frame_current = 0;
			logo_current_img = loader_frames[FRAME_IND_ANIM[still_current][anim_frame_current]];
			time_start = window.performance.now();
		}
	}
	
	// Render film grain pattern
	GenNoise();
	Draw();
    requestAnimationFrame(Loop);
}