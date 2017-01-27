/*
	--------------
	SccTakeTheTour
	--------------
*/

define(function(require, exports, module) {
    var $ = require('jquery');
	var SimpleSplunkView = require('splunkjs/mvc/simplesplunkview');
    var SplunkUtils = require('splunkjs/mvc/utils');
	require("css!./scc_takethetour.css");
	
    var SccTakeTheTour = SimpleSplunkView.extend({
        className: "scc-takethetour",
		options: {
			title: "Take the tour",
			width: 60,
			close_btn_label: "Close",
			no_more_label: "Do not show this tour again",
            hide_container: false,
            show_credits: false,
			cookie_name_suffix: "",
			backdrop_close: true,
			keyboard_close: true
        },

        initialize: function() {
			SimpleSplunkView.prototype.initialize.apply(this, arguments);

            // Treat "hide_container" setting
            if(this.settings.get('hide_container') == true){
                this.$el.parent().css({
                    'padding':0,
                    'margin':0,
                    'height':'0px',
                    'width':'0px'
                })    
            }
            
			return this;
		},

		render: function() {
			this.$el.html('');

            // Cookie stuff
			var cookie_name_suffix = this.settings.get('cookie_name_suffix') == "" ? "" : '_' + this.settings.get('cookie_name_suffix');
            var ck_name = 'scc_takethetour_' + SplunkUtils.getCurrentApp() + cookie_name_suffix;

            function getCookie(ck_name) {
				var oRegex = new RegExp("(?:; )?" + ck_name + "=([^;]*);?");
				return oRegex.test(document.cookie) ? decodeURIComponent(RegExp["$1"]) : null;
			}
            
			function setCookie(ck_name) {
				document.cookie = ck_name + "= scc-takethetour";
			}
				
			// GENERATE BOOTSTRAP MODAL
			// ------------------------
			if(typeof this.settings.get('user_slides') !== 'undefined' 
				&& $('#'+this.settings.get('user_slides')).length == 1
				&& getCookie(ck_name) == null){

				var html_tpl = '<div class="scc-takethetour modal fade" id="scc-takethetour-modal" tabindex="-1" role="dialog" aria-labelledby="scc-takethetour-modal">'
								+ 	'<div class="modal-dialog" role="document">'
								+		'<div class="modal-content">'
								+ 			'<div class="modal-header">'
								+				'<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
								+				'<h4 class="modal-title" id="myModalLabel">' + this.settings.get('title') + '</h4>'
								+			'</div>'
								+			'<div class="modal-body">'
								+				'<div class="scc-takethetour-nav">'
								+					'<button class="prev btn btn-default disabled"><span class="caret"></span></button>'
								+					'<div></div>'
								+					'<button class="next btn btn-default"><span class="caret"></span></button>'
								+ 				'</div>'
								+				'<ul class="scc-takethetour-slides"></ul>'
								+ 			'</div>'
								+ 			'<div class="modal-footer">'
								+				'<label class="never-show-again"><input type="checkbox">' + this.settings.get('no_more_label') + '</label>'
								+				'<button type="button" class="btn btn-default" data-dismiss="modal">' + this.settings.get('close_btn_label') + '</button>'
								+ 			'</div>'
								+ 		'</div>'
								+ 	'</div>'
								+ '</div>';
				this.$el.html(html_tpl);
                
				var $user_slides = $('#'+this.settings.get('user_slides')+' li');
				
				var $modal = this.$el.find('#scc-takethetour-modal');
				$modal.css({width:this.settings.get('width') + "%", "margin-left": "-" + this.settings.get('width')/2 + "%"});
				
				var $modal_body = this.$el.find('#scc-takethetour-modal .modal-body');
				var $slides = this.$el.find('.scc-takethetour-slides');
				var $slides_nav = this.$el.find('.scc-takethetour-nav');
				var $slides_nav_prev = $slides_nav.find('.prev');
				var $slides_nav_next = $slides_nav.find('.next');
				var $slides_nav_links = $slides_nav.find('div');
				var $checkbox = this.$el.find('.never-show-again input');
				
				var active_slide_id = 0;
				var max_slide_id = $user_slides.length - 1;

                // Treat "show_credits" setting
                if(this.settings.get('show_credits') === true){
                    var html_credits = '<div class="credits">'
                                        +   'Powered by <a href="http://www.splunk.com" target="_blank">Splunk</a> and <a href="https://github.com/ftoulouse/splunk-components-collection" target="_blank">Scc</a>'
                                        + '</div>';
                    $modal.find('.modal-footer').append(html_credits);
                }

				$user_slides.each(function(idx){
					$slides_nav_links.append('<button class="btn btn-default" data-slide-id="' + idx + '">' + (idx + 1) + '</button>');
					$slides.append($user_slides.eq(idx));

					idx == 0 ? $slides_nav_links.find('button').eq(idx).addClass('btn-primary') : $slides.find('li').eq(idx).addClass('hide');
				});
                $('#'+this.settings.get('user_slides')).remove();
                

				// EVENTS
				// ------
				$slides_nav_prev.on('click', function(){
					if(!$(this).hasClass('disabled')){
						slidesManagr(active_slide_id - 1);
					}
				});
				$slides_nav_next.on('click', function(){
					if(!$(this).hasClass('disabled')){
						slidesManagr(active_slide_id + 1);
					}
				});
				$slides_nav_links.on('click', function(e){
					slidesManagr($(e.target).attr('data-slide-id'));
				});

				// Add / remove vertical scrollbar on page resize
				function isScrollNeeded(){
					var overflow_y = $slides_nav.outerHeight(true) + $slides.outerHeight() > $modal_body.height() ? 'scroll' : 'none'; 
					$modal_body.css('overflow-y', overflow_y);
				};
				
				// Hide / show slides and slides navigation
				function slidesManagr(slide_id){	
					slide_id = parseInt(slide_id);

					// Manage slides
					$slides.find('li').eq(active_slide_id).addClass('hide');
					$slides_nav_links.find('button').eq(active_slide_id).removeClass('btn-primary')
					
					$slides.find('li').eq(slide_id).removeClass('hide');
					$slides_nav_links.find('button').eq(slide_id).addClass('btn-primary');
					
					// Manage nav
					if(slide_id == 0){
						if(!$slides_nav_prev.hasClass('disabled')){
							$slides_nav_prev.addClass('disabled');
						}
						if($slides_nav_next.hasClass('disabled')){
							$slides_nav_next.removeClass('disabled');
						}
					}
					
					else if(slide_id == max_slide_id){
						if(!$slides_nav_next.hasClass('disabled')){
							$slides_nav_next.addClass('disabled');
						}
						if($slides_nav_prev.hasClass('disabled')){
							$slides_nav_prev.removeClass('disabled');
						}
					}
					
					else{
						if($slides_nav_prev.hasClass('disabled')){
							$slides_nav_prev.removeClass('disabled');
						}
						if($slides_nav_next.hasClass('disabled')){
							$slides_nav_next.removeClass('disabled');
						}
					}

					active_slide_id = slide_id;
					isScrollNeeded();					
				}

				$(window).resize(function(){
					isScrollNeeded();
				});

				// Treat "backdrop_close" and "keyboard_close" settings
				var modal_backdrop = this.settings.get('backdrop_close') === true ? true : 'static';
				var modal_keyboard = this.settings.get('keyboard_close') === true ? true : false;		
					
				$modal
				.on('shown.bs.modal', function(e){
					// Prevents page body scrolling if modal content is scrollable
					$('body').css({overflow:"hidden", position:"fixed", width: "100%"});
					isScrollNeeded();
				})
				.on('hide.bs.modal', function(e){
					// Give back inherited overflow attributes to the body
					$('body').css({overflow:"inherit", position:"inherit", width: "inherit"});
					
					// Never show the tour again until navigator cookie is not deleted by user
					if($checkbox.is(':checked')){
						setCookie(ck_name);
					}
				})
				.modal({
					backdrop: modal_backdrop,
					keyboard: modal_keyboard
				});
			}

			return this;
		}
	});
	
	return SccTakeTheTour;
});
