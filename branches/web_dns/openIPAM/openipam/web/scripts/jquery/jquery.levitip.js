(function($)
{
	var activeTip = null, 
		sourceHandlers = {}, 
		$tip = null, 
		$innerTip = null,
		defaults = {
			sourceType: 'attribute',
			source: 'title',
			activateOn: 'hover',
			insertInto: 'body',
			addClass: 'levitip',
			topOffset: 10,
			leftOffset: 10,
			closeDelay: 100,
			dropShadow: true,
			useHoverIntent: true,
			hiSensitivity: 7,
			hiInterval: 50,
			onOpen: function(){},
			onClose: function(){}
		},
		mouseOver = $.fn.jquery <= "1.2.1" ? 'mouseover' : 'mouseenter',
		mouseOut = $.fn.jquery <= "1.2.1" ? 'mouseout' : 'mouseleave';

	$.extend({
		LeviTip: function(target, options)
		{
			this.init(target, options);
		}
	});
	$.extend($.LeviTip, {
		addSourceHandler : function(handler)
		{
			if ( handler.get && handler.type )
				sourceHandlers[handler.type] = handler;
		},
		closeLeviTip : function()
		{
			if ( activeTip )
				activeTip.close();
		},
		setDefaults : function(d)
		{
			$.extend(defaults, d);
		},
		prototype: {
			init : function(target, o)
			{
				if ( !target )
				{
					return;
				}

				this.settings = $.extend({}, defaults, o);
				this.target = target;
				this.timer = this.tipHover = false;
				this.handler = sourceHandlers[this.settings.sourceType] || 0;
				this.pos = {cx:0, cy:0, px: 0, py: 0};

				var self = this,
					onHover = (this.settings.activateOn == 'hover' ? function(e)
					{
						if ( self.settings.activateOn == 'hover' )
							self.hoverIn(e);
					} : function(){});

				if ( !$tip )
				{
					$innerTip = $('<div class="innerbox"></div>');
					$tip = $('<div><div class="shadowbox1"></div><div class="shadowbox2"></div><div class="shadowbox3"></div></div>')
								.append($innerTip);
					$tip.css({position:'absolute', display: 'none'}).addClass('levitipouter').appendTo('body');
					if ( $.browser.msie && (!$.browser.version || parseInt($.browser.version) <= 6) && $.fn.bgiframe )
					{
						$tip.bgiframe();
					}
				}

				if ( !this.handler )
				{
					return;
				}
				if ( this.handler.prepare )
				{
					this.handler.prepare(this);
				}

				if ( $.fn.hoverIntent && this.settings.useHoverIntent )
				{
					$(target).hoverIntent({
						interval: this.settings.hiInterval,
						sensitivity: this.settings.hiSensitivity,
						over: onHover,
						out: function()
						{
							self.hoverOut();
						},
						timeout: 0
					});
				}
				else
				{
					$(target).hover(onHover, function()
					{
						self.hoverOut();
					});
				}
				if ( this.settings.activateOn == 'click' )
				{
					$(target).click(function(e){
						self.hoverIn(e);
						return false;
					});
				}
			},
			hoverIn: function(e)
			{
				if ( activeTip ) //already a levitip open?
				{
					if ( activeTip == this ) //the current one is already open?
					{
						if ( this.timer ) //is there a closetimer running?
						{
							clearTimeout(this.timer);
						}
						return;
					}
					else //close the other levitip
					{
						activeTip.close();
						activeTip = null;
					}
				}
				var into = ( this.settings.insertInto == 'target' ) ? this.target : 
								( this.settings.insertInto == 'body' ) ? 'body' : this.settings.insertInto;

				$tip.appendTo(into).css({visibility: 'hidden', display:'block'});
				var ins = this.handler.get(this);
				if ( !ins )
					return;
				$innerTip.html(ins).children().show();

				if ( this.settings.addClass )
				{
					$innerTip.addClass(this.settings.addClass);
				}
				if ( this.settings.dropShadow )
				{
					$tip.addClass('outerbox');
				}
				this.pos = {cx: e.clientX, cy: e.clientY, px: e.pageX, py: e.pageY};
				this.setPosition();
				$tip.css({display:'none', visibility: ''}).show();
				activeTip = this;
				if ( this.settings.insertInto == 'body' )
				{
					var self = this;
					$tip.hover(function(e){
						self.tipHoverIn(e);
					},
					function(){
						self.tipHoverOut();
					});
				}
				if ( this.settings.onOpen )
				{
					this.settings.onOpen($tip, this.target);
				}
			},
			hoverOut: function()
			{
				var self = this;
				//close levitip after delay
				this.timer = setTimeout(function(){
					if ( !self.tipHover )
					{
						self.close();
					}
				}, this.settings.closeDelay);
			},
			tipHoverIn: function()
			{
				this.tipHover = true;
			},
			tipHoverOut: function()
			{
				this.tipHover = false;
				this.hoverOut();
			},
			setPosition: function()
			{
				var posX, posY, ww = $(window).width(), wh = $(window).height(), $op, opo;
				$op = $tip.offsetParent();
				opo = ( this.settings.insertInto == 'body' ) ? {left:0,top:0,scrollLeft:0,scrollTop:0} : $op.offset();
				if ( this.settings.insertInto == 'target' && $op.css('position') == 'fixed' )
				{
					posX = this.pos.cx;
					posY = this.pos.cy;
				}
				else
				{
					posX = this.pos.px;
					posY = this.pos.py;
				}
				posX += this.settings.leftOffset - opo.left - opo.scrollLeft;
				posY += this.settings.topOffset - opo.top - opo.scrollTop;
				if ( ww < this.pos.cx + $tip[0].clientWidth + this.settings.leftOffset ) //outside on the right side?
				{
					var wsl = $(window).scrollLeft();
					posX -= $tip[0].clientWidth + this.settings.leftOffset * 2;
					if ( opo.left - wsl + posX < 0 ) //and now outside on the left? :)
					{
						posX -= opo.left - wsl + posX;
					}
				}
				if ( wh < this.pos.cy + $tip[0].clientHeight + this.settings.topOffset ) //outside on the bottom?
				{
					var wst = $(window).scrollTop();
					posY -= $tip[0].clientHeight + this.settings.topOffset * 2;
					if ( opo.top - wst + posY < 0 ) //outside on the top?
					{
						posY -= opo.top - wst + posY;
					}
				}
				$tip.css({left: posX, top: posY});
			},
			close: function()
			{
				if ( this.timer )
				{
					clearTimeout(this.timer);
				}
				$tip.hide().unbind(mouseOver).unbind(mouseOut).css({left:0, top:0}).removeClass('outerbox');

				if ( this.settings.addClass )
				{
					$innerTip.removeClass(this.settings.addClass);
				}

				activeTip = false;
				if ( this.handler.end )
				{
					this.handler.end(this);
				}
				if ( this.settings.onClose )
				{
					this.settings.onClose($tip, this.target);
				}
			}
		}
	});
	$.fn.extend({
		leviTip: function(options)
		{
			return this.each(function(){
				new $.LeviTip(this, options);
			});
		}
	});

	$.LeviTip.addSourceHandler({
		type: 'attribute',
		get: function(levitip)
		{
			var attr = $(levitip.target).attr(levitip.settings.source);
			if ( levitip.settings.source == 'title' )
			{
				levitip.titleAttr = attr;
				$(levitip.target).attr('title', '');
			}
			return attr;
		},
		end: function(levitip)
		{
			if ( levitip.settings.source == 'title' && levitip.titleAttr )
			{
				$(levitip.target).attr('title', levitip.titleAttr);
			}
		}
	});
	$.LeviTip.addSourceHandler({
		type: 'element',
		prepare: function(levitip)
		{
			if ( levitip.settings.hideSourceElement )
			{
				$(levitip.settings.source).hide();
			}
		},
		get: function(levitip)
		{
			var $e = [];
			if ( levitip.settings.source )
			{
				$e = $(levitip.settings.source);
				if ( $e.length )
					$e = $e.clone(true).show();
			}
			return $e;
		}
	});
	$.LeviTip.addSourceHandler({
		type: 'firstchild',
		prepare: function(levitip)
		{
			if ( levitip.settings.hideSourceElement )
			{
				$(levitip.target.firstChild).hide();
			}
		},
		get: function(levitip)
		{
			var $e = $(levitip.target.firstChild);
			if ( $e.length )
				$e = $e.clone(true).show();
			return $e;
		}
	});
})(jQuery);