/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Open config/default.json and set your config values before running this code. 
 * You can also set them using environment variables.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running. Used to point to scripts and 
// assets located at this address. DO NOT INCLUDE THE PROTOCOL
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

// The protocol must be HTTPS so don't allow it to be configurable
// avoid accidental misconfiguration by hard coding it
const IMG_BASE_PATH = 'https://' + SERVER_URL + "/assets/screenshots/";

// make sure that everything has been properly configured
if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * your App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // In DEV, log an error. In PROD, throw an error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("[app.get] Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // entries may be batched so iterate over each one
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {

        let propertyNames = [];
        for (var prop in messagingEvent) { propertyNames.push(prop)}
        console.log("[app.post] Webhook received a messagingEvent with properties: ", propertyNames.join());
        
        if (messagingEvent.message) {
          // someone sent a message
          receivedMessage(messagingEvent);

        } else if (messagingEvent.delivery) {
          // messenger platform sent a delivery confirmation
          receivedDeliveryConfirmation(messagingEvent);

        } else if (messagingEvent.postback) {
          // user replied by tapping one of our postback buttons
          receivedPostback(messagingEvent);

        } else {
          console.log("[app.post] Webhook is not prepared to handle this message.");

        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var pageID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("[receivedMessage] user (%d) page (%d) timestamp (%d) and message (%s)", 
    senderID, pageID, timeOfMessage, JSON.stringify(message));

  if (message.quick_reply) {
    console.log("[receivedMessage] quick_reply.payload (%s)", 
      message.quick_reply.payload);
    handleQuickReplyResponse(event);
    return;
  }

  var messageText = message.text;
  if (messageText) {
    sendTextMessage(senderID, messageText);
  }
}

/*
 * Someone tapped one of the Quick Reply buttons so 
 * respond with the appropriate content
 *
 */
function handleQuickReplyResponse(event) {
  var senderID = event.sender.id;
  var pageID = event.recipient.id;
  var message = event.message;
  var quickReplyPayload = message.quick_reply.payload;
  
  console.log("[handleQuickReplyResponse] Handling quick reply response (%s) from sender (%d) to page (%d) with message (%s)", 
    quickReplyPayload, senderID, pageID, JSON.stringify(message));
  
  // use linear conversation with one interaction per piece of content
  // respondToHelpRequestWithLinearPhotos(senderID, quickReplyPayload);
  
  // use branched conversation with one interaction per feature (each of which contains a variable number of content pieces)
  respondToHelpRequestWithTemplates(senderID, quickReplyPayload);
  
}

/*
 * This response uses templateElements to present the user with a carousel
 * You send ALL of the content for the selected feature and they can 
 * swipe from side to side to see it
 *
 */
function respondToHelpRequestWithTemplates(recipientId, requestForHelpOnFeature) {
  console.log("[respondToHelpRequestWithTemplates] handling help request for %s",
    requestForHelpOnFeature);
  var templateElements = [];
  var sectionButtons = [];
  // each button must be of type postback but title
  // and payload are variable depending on which 
  // set of options you want to provide
  var addSectionButton = function(title, payload) {
    sectionButtons.push({
      type: 'postback',
      title: title,
      payload: payload
    });
  }

  // Since there are only four options in total, we will provide 
  // buttons for each of the remaining three with each section. 
  // This provides the user with maximum flexibility to navigate

  switch (requestForHelpOnFeature) {
    case 'QR_ROTATION_1':
      addSectionButton('Photo', 'QR_PHOTO_1');
      addSectionButton('Caption', 'QR_CAPTION_1');
      addSectionButton('Background', 'QR_BACKGROUND_1');
      
      templateElements.push(
        {
          title: "Rotation",
          subtitle: "portrait mode",
          image_url: IMG_BASE_PATH + "01-rotate-landscape.png",
          buttons: sectionButtons 
        }, 
        {
          title: "Rotation",
          subtitle: "landscape mode",
          image_url: IMG_BASE_PATH + "02-rotate-portrait.png",
          buttons: sectionButtons 
        }
      );
    break; 
    case 'QR_PHOTO_1':
      addSectionButton('Rotation', 'QR_ROTATION_1');
      addSectionButton('Caption', 'QR_CAPTION_1');
      addSectionButton('Background', 'QR_BACKGROUND_1');

      templateElements.push(
        {
          title: "Photo Picker",
          subtitle: "click to start",
          image_url: IMG_BASE_PATH + "03-photo-hover.png",
          buttons: sectionButtons 
        }, 
        {
          title: "Photo Picker",
          subtitle: "Downloads folder",
          image_url: IMG_BASE_PATH + "04-photo-list.png",
          buttons: sectionButtons 
        },
        {
          title: "Photo Picker",
          subtitle: "photo selected",
          image_url: IMG_BASE_PATH + "05-photo-selected.png",
          buttons: sectionButtons 
        }        
      );
    break; 
    case 'QR_CAPTION_1':
      addSectionButton('Rotation', 'QR_ROTATION_1');
      addSectionButton('Photo', 'QR_PHOTO_1');
      addSectionButton('Background', 'QR_BACKGROUND_1');

      templateElements.push(
        {
          title: "Caption",
          subtitle: "click to start",
          image_url: IMG_BASE_PATH + "06-text-hover.png",
          buttons: sectionButtons 
        }, 
        {
          title: "Caption",
          subtitle: "enter text",
          image_url: IMG_BASE_PATH + "07-text-mid-entry.png",
          buttons: sectionButtons 
        },
        {
          title: "Caption",
          subtitle: "click OK",
          image_url: IMG_BASE_PATH + "08-text-entry-done.png",
          buttons: sectionButtons 
        },
        {
          title: "Caption",
          subtitle: "Caption done",
          image_url: IMG_BASE_PATH + "09-text-complete.png",
          buttons: sectionButtons 
        }
      );
    break; 
    case 'QR_BACKGROUND_1':
      addSectionButton('Rotation', 'QR_ROTATION_1');
      addSectionButton('Photo', 'QR_PHOTO_1');
      addSectionButton('Caption', 'QR_CAPTION_1');

      templateElements.push(
        {
          title: "Background Color Picker",
          subtitle: "click to start",
          image_url: IMG_BASE_PATH + "10-background-picker-hover.png",
          buttons: sectionButtons 
        },
        {
          title: "Background Color Picker",
          subtitle: "click current color",
          image_url: IMG_BASE_PATH + "11-background-picker-appears.png",
          buttons: sectionButtons 
        },
        {
          title: "Background Color Picker",
          subtitle: "select new color",
          image_url: IMG_BASE_PATH + "12-background-picker-selection.png",
          buttons: sectionButtons 
        }, 
        {
          title: "Background Color Picker",
          subtitle: "click ok",
          image_url: IMG_BASE_PATH + "13-background-picker-selection-made.png",
          buttons: sectionButtons 
        },
        {
          title: "Background Color Picker",
          subtitle: "color is applied",
          image_url: IMG_BASE_PATH + "14-background-changed.png",
          buttons: sectionButtons 
        }
      );
    break; 
  }

  if (templateElements.length < 2) {
    console.error("each template should have at least two elements");
  }
  
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: templateElements
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * This response uses image attachments to illustrate each step of each feature.
 * This is less flexible because you are limited in the number of options you can
 * provide for the user. This technique is best for cases where the content should
 * be consumed in a strict linear order.
 *
 */
function respondToHelpRequestWithLinearPhotos(recipientId, helpRequestType) {
  var textToSend = '';
  var quickReplies = [
    {
      "content_type":"text",
      "title":"Restart",
      "payload":"QR_RESTART"
    }, // this option should always be present because it allows the user to start over
    {
      "content_type":"text",
      "title":"Continue",
      "payload":""
    } // the Continue option only makes sense if there is more content to show 
      // remove this option when you are at the end of a branch in the content tree
      // i.e.: when you are showing the last message for the selected feature
  ];
  
  // to send an image attachment in a message, just set the payload property of this attachment object
  // if the payload property is defined, this will be added to the message before it is sent
  var attachment = {
    "type": "image",
    "payload": ""
  };

  switch(helpRequestType) {
    case 'QR_RESTART' :
      sendHelpOptions(recipientId);
      return;
    break;
    
    // the Rotation feature
    case 'QR_ROTATION_1' :
      textToSend = 'Click the Rotate button to toggle the poster\'s orientation between landscape and portrait mode.';
      quickReplies[1].payload = "QR_ROTATION_2";
    break; 
    case 'QR_ROTATION_2' :
      // 1 of 2 (portrait, landscape)
      attachment.payload = {
        url: IMG_BASE_PATH + "01-rotate-landscape.png"
      }
      quickReplies[1].payload = "QR_ROTATION_3";
    break; 
    case 'QR_ROTATION_3' :
      // 2 of 2 (portrait, landscape)
      attachment.payload = {
        url: IMG_BASE_PATH + "02-rotate-portrait.png"
      }
      quickReplies.pop();
      quickReplies[0].title = "Explore another feature";
    break; 
    // the Rotation feature


    // the Photo feature
    case 'QR_PHOTO_1' :
      textToSend = 'Click the Photo button to select an image to use on your poster. We recommend visiting https://unsplash.com/random from your device to seed your Downloads folder with some images before you get started.';
      quickReplies[1].payload = "QR_PHOTO_2";
    break; 
    case 'QR_PHOTO_2' :
      // 1 of 3 (placeholder image, Downloads folder, poster with image)
      attachment.payload = {
        url: IMG_BASE_PATH + "03-photo-hover.png"
      }
      quickReplies[1].payload = "QR_PHOTO_3";
    break; 
    case 'QR_PHOTO_3' :
      // 2 of 3 (placeholder image, Downloads folder, poster with image)
      attachment.payload = {
        url: IMG_BASE_PATH + "04-photo-list.png"
      }
      quickReplies[1].payload = "QR_PHOTO_4";
    break; 
    case 'QR_PHOTO_4' :
      // 3 of 3 (placeholder image, Downloads folder, poster with image)
      attachment.payload = {
        url: IMG_BASE_PATH + "05-photo-selected.png"
      }
      quickReplies.pop();
      quickReplies[0].title = "Explore another feature";
    break; 
    // the Photo feature


    // the Caption feature
    case 'QR_CAPTION_1' :
      textToSend = 'Click the Text button to set the caption that appears at the bottom of the poster.';
      quickReplies[1].payload = "QR_CAPTION_2";
    break; 
    case 'QR_CAPTION_2' :
      // 1 of 4 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "06-text-hover.png"
      }
      quickReplies[1].payload = "QR_CAPTION_3";
    break; 
    case 'QR_CAPTION_3' :
      // 2 of 4: (hover, entering caption, mid-edit, poster with new caption
      attachment.payload = {
        url: IMG_BASE_PATH + "07-text-mid-entry.png"
      }
      quickReplies[1].payload = "QR_CAPTION_4";
    break; 
    case 'QR_CAPTION_4' :
      // 3 of 4 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "08-text-entry-done.png"
      }
      quickReplies[1].payload = "QR_CAPTION_5";
    break; 
    case 'QR_CAPTION_5' :
      // 4 of 4 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "09-text-complete.png"
      }
      quickReplies.pop();
      quickReplies[0].title = "Explore another feature";
    break; 
    // the Caption feature



    // the Color Picker feature
    case 'QR_BACKGROUND_1' :
      textToSend = 'Click the Background button to select a background color for your poster.';
      quickReplies[1].payload = "QR_BACKGROUND_2";
    break; 
    case 'QR_BACKGROUND_2' :
      // 1 of 5 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "10-background-picker-hover.png"
      }
      quickReplies[1].payload = "QR_BACKGROUND_3";
    break; 
    case 'QR_BACKGROUND_3' :
      // 2 of 5 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "11-background-picker-appears.png"
      }
      quickReplies[1].payload = "QR_BACKGROUND_4";
    break; 
    case 'QR_BACKGROUND_4' :
      // 3 of 5 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "12-background-picker-selection.png"
      }
      quickReplies[1].payload = "QR_BACKGROUND_5";
    break; 
    case 'QR_BACKGROUND_5' :
      // 4 of 5 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "13-background-picker-selection-made.png"
      }
      quickReplies[1].payload = "QR_BACKGROUND_6";
    break; 
    case 'QR_BACKGROUND_6' :
      // 5 of 5 (hover, entering caption, mid-edit, poster with new caption)
      attachment.payload = {
        url: IMG_BASE_PATH + "14-background-changed.png"
      }
      quickReplies.pop();
      quickReplies[0].title = "Explore another feature";
    break; 
    // the Color Picker feature

    default : 
      sendHelpOptions(recipientId);
      return;

    break;
  }

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: textToSend,
      quick_replies: quickReplies
    },
  };
  if (attachment.payload !== "") {
    messageData.message.attachment = attachment;
    // text can not be specified when you're sending an attachment
    delete messageData.message.text;
  }

  callSendAPI(messageData);
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id; // the user who sent the message
  var recipientID = event.recipient.id; // the page they sent it from
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("[receivedDeliveryConfirmation] Message with ID %s was delivered", 
        messageID);
    });
  }

  console.log("[receivedDeliveryConfirmation] All messages before timestamp %d were delivered.", watermark);
}

/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("[receivedPostback] from user (%d) on page (%d) with payload ('%s') " + 
    "at (%d)", senderID, recipientID, payload, timeOfPostback);

  respondToHelpRequestWithTemplates(senderID, payload);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText, // utf-8, 640-character max
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("[callSendAPI] Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("[callSendAPI] Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("[callSendAPI] Send API call failed", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

/*
 * Start server
 * Webhooks must be available via SSL with a certificate signed by a valid 
 * certificate authority.
 */
app.listen(app.get('port'), function() {
  console.log('[app.listen] Node app is running on port', app.get('port'));
});

module.exports = app;

