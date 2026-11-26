using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

namespace SmartCCleaner
{
    public static class UiTheme
    {
        public static readonly SolidColorBrush BgCanvas = Brush("#F3F6FA");
        public static readonly SolidColorBrush BgCard = Brush("#FFFFFF");
        public static readonly SolidColorBrush BgSubtle = Brush("#F8FAFC");
        public static readonly SolidColorBrush BorderLight = Brush("#E2E8F0");
        public static readonly SolidColorBrush BorderFocus = Brush("#2563EB");

        public static readonly SolidColorBrush TextPrimary = Brush("#0F172A");
        public static readonly SolidColorBrush TextSecondary = Brush("#475569");
        public static readonly SolidColorBrush TextMuted = Brush("#94A3B8");

        public static readonly SolidColorBrush AccentBlue = Brush("#2563EB");
        public static readonly SolidColorBrush AccentBlueHover = Brush("#1D4ED8");
        public static readonly SolidColorBrush AccentBlueSoft = Brush("#EFF6FF");

        public static readonly SolidColorBrush SafeGreen = Brush("#10B981");
        public static readonly SolidColorBrush SafeGreenHover = Brush("#059669");
        public static readonly SolidColorBrush SafeGreenSoft = Brush("#ECFDF5");
        public static readonly SolidColorBrush SafeGreenText = Brush("#047857");

        public static readonly SolidColorBrush WarnAmber = Brush("#F59E0B");
        public static readonly SolidColorBrush WarnAmberSoft = Brush("#FFFBEB");
        public static readonly SolidColorBrush WarnAmberText = Brush("#B45309");

        public static readonly SolidColorBrush DangerRed = Brush("#EF4444");
        public static readonly SolidColorBrush DangerRedHover = Brush("#DC2626");
        public static readonly SolidColorBrush DangerRedSoft = Brush("#FEF2F2");
        public static readonly SolidColorBrush DangerRedText = Brush("#B91C1C");

        public static readonly SolidColorBrush AdminPurpleSoft = Brush("#F5F3FF");
        public static readonly SolidColorBrush AdminPurpleText = Brush("#6D28D9");

        public static readonly FontFamily MainFont = new FontFamily("Microsoft YaHei UI, Segoe UI");
        public static readonly FontFamily MonoFont = new FontFamily("Consolas, Courier New");

        public static SolidColorBrush Brush(string hex)
        {
            var color = (Color)ColorConverter.ConvertFromString(hex);
            var b = new SolidColorBrush(color);
            b.Freeze();
            return b;
        }

        public static DropShadowEffect CardShadow()
        {
            return new DropShadowEffect
            {
                Color = Color.FromRgb(15, 23, 42),
                BlurRadius = 16,
                ShadowDepth = 2,
                Opacity = 0.06,
                Direction = 270
            };
        }

        public static Border CreateCard(UIElement child, Thickness padding)
        {
            return new Border
            {
                Background = BgCard,
                BorderBrush = BorderLight,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = padding,
                Effect = CardShadow(),
                Child = child
            };
        }

        public static Border CreatePill(string text, SolidColorBrush bg, SolidColorBrush fg)
        {
            var tb = new TextBlock
            {
                Text = text,
                Foreground = fg,
                FontFamily = MainFont,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            return new Border
            {
                Background = bg,
                CornerRadius = new CornerRadius(999),
                Padding = new Thickness(8, 2.5, 8, 2.5),
                VerticalAlignment = VerticalAlignment.Center,
                Child = tb
            };
        }

        public static Button CreateButton(string text, SolidColorBrush bg, SolidColorBrush hoverBg, SolidColorBrush fg, double height, Thickness padding)
        {
            var btn = new Button
            {
                Content = text,
                Foreground = fg,
                Background = bg,
                FontFamily = MainFont,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Height = height,
                Padding = padding,
                Cursor = Cursors.Hand,
                BorderThickness = new Thickness(0)
            };

            btn.Template = BuildRoundedButtonTemplate(bg, hoverBg, null, 8);
            return btn;
        }

        public static Button CreateOutlineButton(string text, double height, Thickness padding)
        {
            var btn = new Button
            {
                Content = text,
                Foreground = TextPrimary,
                Background = BgCard,
                FontFamily = MainFont,
                FontSize = 12.5,
                FontWeight = FontWeights.Medium,
                Height = height,
                Padding = padding,
                Cursor = Cursors.Hand,
                BorderThickness = new Thickness(1)
            };

            btn.Template = BuildRoundedButtonTemplate(BgCard, BgSubtle, BorderLight, 8);
            return btn;
        }

        public static ControlTemplate BuildRoundedButtonTemplate(SolidColorBrush normalBg, SolidColorBrush hoverBg, SolidColorBrush borderBrush, double radius)
        {
            var template = new ControlTemplate(typeof(Button));
            var borderFactory = new FrameworkElementFactory(typeof(Border));
            borderFactory.Name = "bd";
            borderFactory.SetValue(Border.BackgroundProperty, normalBg);
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(radius));
            borderFactory.SetValue(Border.SnapsToDevicePixelsProperty, true);

            if (borderBrush != null)
            {
                borderFactory.SetValue(Border.BorderBrushProperty, borderBrush);
                borderFactory.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            }

            var contentFactory = new FrameworkElementFactory(typeof(ContentPresenter));
            contentFactory.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            contentFactory.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            contentFactory.SetValue(ContentPresenter.MarginProperty, new TemplateBindingExtension(Button.PaddingProperty));

            borderFactory.AppendChild(contentFactory);
            template.VisualTree = borderFactory;

            var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            hoverTrigger.Setters.Add(new Setter(Border.BackgroundProperty, hoverBg, "bd"));
            template.Triggers.Add(hoverTrigger);

            var disabledTrigger = new Trigger { Property = UIElement.IsEnabledProperty, Value = false };
            disabledTrigger.Setters.Add(new Setter(UIElement.OpacityProperty, 0.45, "bd"));
            template.Triggers.Add(disabledTrigger);

            return template;
        }

        public static Path CreateArcPath(double centerX, double centerY, double radius, double startAngleDeg, double sweepAngleDeg, SolidColorBrush stroke, double thickness)
        {
            if (sweepAngleDeg <= 0.1) sweepAngleDeg = 0.1;
            if (sweepAngleDeg >= 359.9) sweepAngleDeg = 359.9;

            double startRad = (startAngleDeg - 90.0) * Math.PI / 180.0;
            double endRad = (startAngleDeg + sweepAngleDeg - 90.0) * Math.PI / 180.0;

            var startPoint = new Point(centerX + radius * Math.Cos(startRad), centerY + radius * Math.Sin(startRad));
            var endPoint = new Point(centerX + radius * Math.Cos(endRad), centerY + radius * Math.Sin(endRad));

            bool isLargeArc = sweepAngleDeg > 180.0;

            var segment = new ArcSegment
            {
                Point = endPoint,
                Size = new Size(radius, radius),
                IsLargeArc = isLargeArc,
                SweepDirection = SweepDirection.Clockwise
            };

            var figure = new PathFigure
            {
                StartPoint = startPoint,
                IsClosed = false
            };
            figure.Segments.Add(segment);

            var geometry = new PathGeometry();
            geometry.Figures.Add(figure);

            return new Path
            {
                Data = geometry,
                Stroke = stroke,
                StrokeThickness = thickness,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };
        }
    }
}
